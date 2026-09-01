from __future__ import annotations

import ast
import copy
import hashlib
import math
import unittest
from pathlib import Path

from worldforge.provider_evidence.ollama_v2 import (
    ADR0046_RAW_SHA256,
    ADR0046_VOCABULARY_ENTRY_COUNT,
    ADR0046_VOCABULARY_IDS,
    ADR0046_VOCABULARY_REGISTRY_SHA256,
    CORRECTED_EVIDENCE_FOUNDATION_POLICY_FORMAT,
    FORBIDDEN_V1_CUSTODY_HANDOFF_ALIAS,
    V1_DISPOSITION_FORMAT,
    OllamaEvidenceContractError,
    canonical_corrected_evidence_foundation_policy_document,
    canonical_ollama_evidence_bytes,
    canonical_ollama_evidence_hash,
    canonical_v1_disposition_document,
    extract_adr0046_vocabulary_ids,
    validate_adr0046_source,
    validate_corrected_evidence_foundation_policy_document,
    validate_ollama_evidence_document,
    validate_v1_disposition_document,
    vocabulary_registry_sha256,
)

ROOT = Path(__file__).resolve().parents[1]
ADR0046 = ROOT / "docs/decisions/0046-governed-observed-ollama-adapter.md"

EXPECTED_V1_CONTENT_HASH = "ec2fa718852dfc55babd1de180a0e799a87e2542555b231fa88f080873c2e99a"
EXPECTED_V1_SERIALIZED_SHA256 = "b2367c785c7435d678421fe0abfff2b2a583f123081d3adfbef5255a3642b05d"
EXPECTED_V2_CONTENT_HASH = "c4fbf98a52896901bb46732935a7fbef462b7369105dab5bffcff381a3968f73"
EXPECTED_V2_SERIALIZED_SHA256 = "030f2a3432efc21d3f9915cd39575e334c47b24b58770935c5105e8f5d5c1322"

PROTECTED_SHA256 = {
    "examples/multigenre-contracts/agent-harness-minimal/capability-grant.json": (
        "9aa237725ff3600c8085d29a48248124b529ad73dd68e603ba2a7cd99a14407c"
    ),
    "examples/multigenre-contracts/agent-harness-minimal/event-00.json": (
        "058655ed59983e612dfd1435066140d36f591dd767c2de03bb451a1b3991c279"
    ),
    "examples/multigenre-contracts/agent-harness-minimal/event-01.json": (
        "bd6a12671cb8089dcd609a893d5c25c61e4c6ea6f15b78803efb62931d366ac1"
    ),
    "examples/multigenre-contracts/agent-harness-minimal/event-02.json": (
        "f7187d2ed72e7dbe26d81d05f2ab43fe3ec4b603a72ed68f473e8cf128a306f6"
    ),
    "examples/multigenre-contracts/agent-harness-minimal/execution-receipt.json": (
        "dcaa37f483f21203107ea16bc8330b5bd75374aa1124a4ddda16efe4917247d0"
    ),
    "examples/multigenre-contracts/agent-harness-minimal/memory-projection.json": (
        "43cf6a086055e9513accae54c771370f46048f334b1222b9c7685c7ca4abe2c6"
    ),
    "examples/multigenre-contracts/agent-harness-minimal/worker-activation.json": (
        "f8224c8b22ee2836dd14785536abb6c9ed399cc7cce0e63ae49a18fbc044e39f"
    ),
    "schemas/agent-capability-grant.schema.json": (
        "102d55a9934ef97e9d155557f4999c3b8d74654f9eeb566a54d3a6cf2e6b86cf"
    ),
    "schemas/agent-event.schema.json": (
        "82c9a51b913758cbec69cf81c6646a7b52043e16b45a96f60816f74bd63bed27"
    ),
    "schemas/agent-execution-receipt.schema.json": (
        "3ed9fe19b189e47552c2e68aab827e00d148ed209958654754fcbb3e90a54f4a"
    ),
    "schemas/agent-memory-projection.schema.json": (
        "dc3ec9f77f0d85a03033a33acd7e6738467ec668cfb893263b618cb57bc283b4"
    ),
    "schemas/agent-worker-activation.schema.json": (
        "40888648df32abb8c682dfd8e683bf5a4743a9d366905ed8b2ed89d047930d5b"
    ),
    "src/worldforge/agent_harness_contracts.py": (
        "3204a07789e2acbbaead2764aac67bc658c6b575c8d574e07ec06e4027ee1049"
    ),
    "src/worldforge/agent_harness/event_log.py": (
        "025e340983229a176382d0e9bf886796a8924ca38bdc87414c848d7034d30d37"
    ),
    "src/worldforge/agent_harness/provider_catalog.py": (
        "a5188fd01492ed8c91d8aeff497936db17fd970d4d1cb3eea66decfe3f6823d4"
    ),
    "src/worldforge/agent_harness/worker.py": (
        "6b818249f8cca6bcca397f96f5dc37e1e6c13e07f3cb3d7962714556a9396a63"
    ),
    "src/worldforge/agent_harness/worker_registry.py": (
        "fb5a8a8c7d23acbe02dddbb0bd03f3f12ec7b6a26d939bb86f526c319a8f1f73"
    ),
}


def _reseal(document: dict[str, object]) -> dict[str, object]:
    result = copy.deepcopy(document)
    result["content_hash"] = canonical_ollama_evidence_hash(result)
    return result


class ADR0046VocabularyBindingTests(unittest.TestCase):
    def test_raw_adr_and_exact_ordered_registry_are_mechanically_pinned(self) -> None:
        source = ADR0046.read_bytes()

        binding = validate_adr0046_source(source)

        self.assertEqual(ADR0046_RAW_SHA256, hashlib.sha256(source).hexdigest())
        self.assertEqual(ADR0046_VOCABULARY_ENTRY_COUNT, len(binding.vocabulary_ids))
        self.assertEqual(86, len(binding.vocabulary_ids))
        self.assertEqual(tuple(ADR0046_VOCABULARY_IDS), binding.vocabulary_ids)
        self.assertEqual(ADR0046_VOCABULARY_REGISTRY_SHA256, binding.registry_sha256)
        self.assertEqual(
            "518cdc4056f8d4ad3cfa9a28b08dcf2324c4b3833f4bc04fd49a9e8b2bc06ed9",
            vocabulary_registry_sha256(binding.vocabulary_ids),
        )
        self.assertEqual(
            "worldforge_ollama_installation_observation_v1",
            binding.vocabulary_ids[0],
        )
        self.assertEqual(
            "worldforge_ollama_private_evidence_artifact_payload_v1",
            binding.vocabulary_ids[-1],
        )

    def test_forbidden_alias_text_outside_table_is_not_admitted_by_registry(self) -> None:
        source = ADR0046.read_bytes()

        identifiers = extract_adr0046_vocabulary_ids(source)

        self.assertIn(FORBIDDEN_V1_CUSTODY_HANDOFF_ALIAS.encode("ascii"), source)
        self.assertNotIn(FORBIDDEN_V1_CUSTODY_HANDOFF_ALIAS, identifiers)
        self.assertEqual(tuple(ADR0046_VOCABULARY_IDS), identifiers)

    def test_missing_reordered_extra_or_forbidden_registry_entries_fail_closed(self) -> None:
        source = ADR0046.read_bytes()
        first = (
            b"| installation observation | `worldforge_ollama_installation_observation_v1` "
            b"| canonical installation document |\n"
        )
        second = (
            b"| model lock | `worldforge_ollama_model_lock_v1` | manifest plus every blob "
            b"identity |\n"
        )
        self.assertIn(first + second, source)
        mutations = {
            "missing": source.replace(first, b"", 1),
            "reordered": source.replace(first + second, second + first, 1),
            "extra": source.replace(second, second + second, 1),
            "forbidden_alias": source.replace(
                b"worldforge_ollama_installation_observation_v1",
                FORBIDDEN_V1_CUSTODY_HANDOFF_ALIAS.encode("ascii"),
                1,
            ),
        }
        for name, mutated in mutations.items():
            with self.subTest(name=name), self.assertRaisesRegex(
                OllamaEvidenceContractError,
                "adr0046_vocabulary_invalid",
            ):
                validate_adr0046_source(mutated)

    def test_non_table_drift_and_hostile_source_types_fail_closed(self) -> None:
        source = ADR0046.read_bytes()
        drifted = source.replace(b"# ADR-0046:", b"# ADR 0046:", 1)
        for value in (drifted, bytearray(source), source.decode("utf-8"), b"not utf-8: \xff"):
            with self.subTest(value_type=type(value).__name__), self.assertRaises(
                OllamaEvidenceContractError
            ):
                validate_adr0046_source(value)


class OllamaV2CanonicalContractTests(unittest.TestCase):
    def test_v1_disposition_has_one_pinned_canonical_vector_and_closed_defects(self) -> None:
        document = canonical_v1_disposition_document()

        self.assertEqual(V1_DISPOSITION_FORMAT, document["format"])
        self.assertEqual(EXPECTED_V1_CONTENT_HASH, document["content_hash"])
        self.assertEqual(
            EXPECTED_V1_SERIALIZED_SHA256,
            hashlib.sha256(canonical_ollama_evidence_bytes(document)).hexdigest(),
        )
        self.assertEqual(
            [
                "ambient_model_root_custody_unsealed",
                "ambient_release_root_custody_unsealed",
                "nss_supplementary_groups_not_excluded",
                "transient_standard_input_fd_setter_unavailable",
            ],
            document["defect_codes"],
        )
        self.assertEqual(
            {
                "availability": "permanently_unavailable",
                "production_eligible": False,
                "catalog_admission_allowed": False,
                "provider_execution_allowed": False,
                "provider_turn_allowed": False,
                "replay_claim_allowed": False,
                "pricing_claim_allowed": False,
                "migration_allowed": False,
                "conversion_allowed": False,
                "promotion_allowed": False,
            },
            document["disposition"],
        )
        self.assertEqual(document, validate_v1_disposition_document(document))

    def test_v2_policy_has_one_pinned_canonical_vector_and_exact_corrected_authority(self) -> None:
        document = canonical_corrected_evidence_foundation_policy_document()

        self.assertEqual(CORRECTED_EVIDENCE_FOUNDATION_POLICY_FORMAT, document["format"])
        self.assertEqual(EXPECTED_V2_CONTENT_HASH, document["content_hash"])
        self.assertEqual(
            EXPECTED_V2_SERIALIZED_SHA256,
            hashlib.sha256(canonical_ollama_evidence_bytes(document)).hexdigest(),
        )
        self.assertEqual(
            {
                "format": V1_DISPOSITION_FORMAT,
                "content_hash": EXPECTED_V1_CONTENT_HASH,
            },
            document["supersedes"],
        )
        self.assertEqual(
            {
                "installation_mode": "installed_units",
                "socket_unit": "worldforge-ollama-evidence.socket",
                "service_unit": "worldforge-ollama-evidence.service",
                "file_descriptor_name": "ollama-http",
                "standard_input": "fd:ollama-http",
                "descriptor_name_match_required": True,
                "transient_fd_setter_allowed": False,
            },
            document["systemd_socket_activation"],
        )
        self.assertEqual(
            document,
            validate_corrected_evidence_foundation_policy_document(document),
        )

    def test_validators_return_detached_documents_and_cross_formats_never_accept(self) -> None:
        v1 = canonical_v1_disposition_document()
        v2 = canonical_corrected_evidence_foundation_policy_document()

        validated = validate_ollama_evidence_document(v2)
        self.assertEqual(v2, validated)
        self.assertIsNot(v2, validated)
        self.assertIsNot(v2["principal"], validated["principal"])
        validated["principal"]["account"] = "mutated"  # type: ignore[index]
        self.assertEqual(
            "worldforge-ollama-evidence",
            canonical_corrected_evidence_foundation_policy_document()["principal"]["account"],
        )
        with self.assertRaises(OllamaEvidenceContractError):
            validate_v1_disposition_document(v2)
        with self.assertRaises(OllamaEvidenceContractError):
            validate_corrected_evidence_foundation_policy_document(v1)
        with self.assertRaises(OllamaEvidenceContractError):
            validate_ollama_evidence_document(v1, expected_format=v2["format"])
        for hostile_expected_format in (True, 1, [], {"format": V1_DISPOSITION_FORMAT}):
            with self.subTest(expected_format=hostile_expected_format), self.assertRaises(
                OllamaEvidenceContractError
            ):
                validate_ollama_evidence_document(
                    v1,
                    expected_format=hostile_expected_format,
                )

    def test_missing_extra_wrong_types_hashes_and_non_json_values_fail_closed(self) -> None:
        canonical = canonical_corrected_evidence_foundation_policy_document()
        missing = copy.deepcopy(canonical)
        del missing["principal"]
        extra = copy.deepcopy(canonical)
        extra["provider_adapter"] = "forbidden"
        bool_as_int = copy.deepcopy(canonical)
        bool_as_int["policy_generation"] = True
        tuple_instead_of_array = copy.deepcopy(canonical)
        tuple_instead_of_array["principal"]["supplementary_groups"] = ()  # type: ignore[index]
        malformed_hash = copy.deepcopy(canonical)
        malformed_hash["supersedes"]["content_hash"] = "A" * 64  # type: ignore[index]
        non_finite = copy.deepcopy(canonical)
        non_finite["policy_generation"] = math.nan
        for name, document in {
            "missing": missing,
            "extra": extra,
            "bool_as_int": bool_as_int,
            "tuple_instead_of_array": tuple_instead_of_array,
            "malformed_hash": malformed_hash,
            "non_finite": non_finite,
        }.items():
            with self.subTest(name=name), self.assertRaises(OllamaEvidenceContractError):
                validate_corrected_evidence_foundation_policy_document(document)

    def test_v1_identity_registry_and_disposition_drift_fails_when_resealed(self) -> None:
        canonical = canonical_v1_disposition_document()
        mutations = (
            "malformed_adr_id",
            "wrong_adr_hash",
            "malformed_registry_hash",
            "bool_count",
            "production",
            "migration",
            "conversion",
            "promotion",
            "defect",
        )
        for name in mutations:
            document = copy.deepcopy(canonical)
            if name == "malformed_adr_id":
                document["source_adr"]["id"] = "ADR 0046"  # type: ignore[index]
            elif name == "wrong_adr_hash":
                document["source_adr"]["sha256"] = "0" * 64  # type: ignore[index]
            elif name == "malformed_registry_hash":
                source_adr = document["source_adr"]
                source_adr["vocabulary_registry_sha256"] = "0" * 63  # type: ignore[index]
            elif name == "bool_count":
                document["source_adr"]["vocabulary_entry_count"] = True  # type: ignore[index]
            elif name == "production":
                document["disposition"]["production_eligible"] = True  # type: ignore[index]
            elif name == "migration":
                document["disposition"]["migration_allowed"] = True  # type: ignore[index]
            elif name == "conversion":
                document["disposition"]["conversion_allowed"] = True  # type: ignore[index]
            elif name == "promotion":
                document["disposition"]["promotion_allowed"] = True  # type: ignore[index]
            else:
                document["defect_codes"][0] = "invented_defect"  # type: ignore[index]
            with self.subTest(name=name), self.assertRaises(OllamaEvidenceContractError):
                validate_v1_disposition_document(_reseal(document))

        for name, identifiers in {
            "missing": list(ADR0046_VOCABULARY_IDS[:-1]),
            "reordered": [
                ADR0046_VOCABULARY_IDS[1],
                ADR0046_VOCABULARY_IDS[0],
                *ADR0046_VOCABULARY_IDS[2:],
            ],
            "extra": [*ADR0046_VOCABULARY_IDS, ADR0046_VOCABULARY_IDS[-1]],
            "forbidden_alias": [
                *ADR0046_VOCABULARY_IDS,
                FORBIDDEN_V1_CUSTODY_HANDOFF_ALIAS,
            ],
        }.items():
            document = copy.deepcopy(canonical)
            document["source_adr"]["vocabulary_ids"] = identifiers  # type: ignore[index]
            source_adr = document["source_adr"]
            source_adr["vocabulary_entry_count"] = len(identifiers)  # type: ignore[index]
            document["source_adr"]["vocabulary_registry_sha256"] = (  # type: ignore[index]
                vocabulary_registry_sha256(tuple(identifiers))
            )
            with self.subTest(name=name), self.assertRaises(OllamaEvidenceContractError):
                validate_v1_disposition_document(_reseal(document))

    def test_principal_custody_and_socket_activation_drift_fail_even_when_resealed(self) -> None:
        mutations: dict[str, tuple[str, str, object]] = {
            "ambient_ollama": ("principal", "ambient_ollama_allowed", True),
            "wrong_principal": ("principal", "account", "ollama"),
            "supplementary_video": ("principal", "supplementary_groups", ["video"]),
            "nss_extension": ("principal", "nss_supplementary_groups_allowed", True),
            "ambient_release": ("release_custody", "ambient_root_allowed", True),
            "release_symlink": ("release_custody", "final_root_symlink_allowed", True),
            "release_hardlink": ("release_custody", "final_root_hardlink_allowed", True),
            "release_writable": ("release_custody", "final_root_writable_allowed", True),
            "ambient_model": ("model_custody", "ambient_root_allowed", True),
            "model_symlink": ("model_custody", "final_root_symlink_allowed", True),
            "model_hardlink": ("model_custody", "final_root_hardlink_allowed", True),
            "model_writable": ("model_custody", "final_root_writable_allowed", True),
            "transient_fd": (
                "systemd_socket_activation",
                "transient_fd_setter_allowed",
                True,
            ),
            "fd_name_mismatch": (
                "systemd_socket_activation",
                "standard_input",
                "fd:other",
            ),
            "descriptor_match_disabled": (
                "systemd_socket_activation",
                "descriptor_name_match_required",
                False,
            ),
        }
        canonical = canonical_corrected_evidence_foundation_policy_document()
        for name, (section, field, value) in mutations.items():
            document = copy.deepcopy(canonical)
            document[section][field] = value  # type: ignore[index]
            with self.subTest(name=name), self.assertRaises(OllamaEvidenceContractError):
                validate_corrected_evidence_foundation_policy_document(_reseal(document))

    def test_cloud_network_device_and_authority_overclaims_fail_even_when_resealed(self) -> None:
        mutations: dict[str, tuple[str, str, object]] = {
            "cloud_on": ("cloud_network", "ollama_no_cloud", "0"),
            "environment_inheritance": (
                "cloud_network",
                "environment_inheritance_allowed",
                True,
            ),
            "dns": ("cloud_network", "dns_allowed", True),
            "non_loopback": ("cloud_network", "listen_host", "0.0.0.0"),
            "non_loopback_allowed": ("cloud_network", "non_loopback_allowed", True),
            "proxy": ("cloud_network", "proxy_allowed", True),
            "proxy_inheritance": (
                "cloud_network",
                "proxy_environment_inheritance_allowed",
                True,
            ),
            "redirect": ("cloud_network", "redirects_allowed", True),
            "accelerator_group": (
                "device_boundary",
                "supplementary_accelerator_groups",
                ["render"],
            ),
            "device_allow": ("device_boundary", "device_allow_entries", ["char-drm"]),
            "device_path": ("device_boundary", "accelerator_device_paths", ["/dev/dri"]),
            "backend": ("device_boundary", "accelerator_backends", ["cuda"]),
            "accelerator_runtime": (
                "device_boundary",
                "accelerator_runtime_allowed",
                True,
            ),
            "production": ("implementation_state", "production_eligible", True),
            "catalog": ("implementation_state", "catalog_admission_allowed", True),
            "provider_execution": (
                "implementation_state",
                "provider_execution_allowed",
                True,
            ),
            "provider_turn": ("implementation_state", "provider_turn_allowed", True),
            "replay": ("implementation_state", "replay_claim_allowed", True),
            "pricing": ("implementation_state", "pricing_claim_allowed", True),
        }
        canonical = canonical_corrected_evidence_foundation_policy_document()
        for name, (section, field, value) in mutations.items():
            document = copy.deepcopy(canonical)
            document[section][field] = value  # type: ignore[index]
            with self.subTest(name=name), self.assertRaises(OllamaEvidenceContractError):
                validate_corrected_evidence_foundation_policy_document(_reseal(document))


class OllamaV2IsolationTests(unittest.TestCase):
    def test_module_is_pure_and_has_no_execution_or_provider_import_surface(self) -> None:
        module_path = ROOT / "src/worldforge/provider_evidence/ollama_v2.py"
        source = module_path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        import_roots: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                import_roots.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module is not None:
                import_roots.add(node.module.split(".", 1)[0])
        self.assertEqual(
            {"__future__", "copy", "dataclasses", "hashlib", "json", "re"},
            import_roots,
        )
        for forbidden in (
            "agent_harness",
            "ProviderAdapter",
            "ProviderRuntimeCatalog",
            "EventLog",
            "import subprocess",
            "from subprocess",
            "import socket",
            "from socket",
            "import systemd",
            "from systemd",
            "pathlib",
            "open(",
            "requests",
            "httpx",
            "ollama.",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)

    def test_existing_synthetic_runtime_registry_remains_exact_and_excludes_ollama(self) -> None:
        from worldforge.agent_harness.worker_registry import (
            _CodeOwnedRuntimeKey,
            code_owned_provider_catalog,
            runtime_entry,
        )

        entries = tuple(runtime_entry(key) for key in _CodeOwnedRuntimeKey)
        self.assertEqual(
            [
                ("worldforge_conformance_provider", 4, 3),
                ("worldforge_deterministic_probe_provider", 6, 3),
            ],
            [(entry.identifier, entry.revision, entry.protocol_version) for entry in entries],
        )
        catalog = code_owned_provider_catalog()
        self.assertEqual(2, len(catalog.specs))
        self.assertEqual(
            {entry.identifier for entry in entries},
            {spec.runtime_id for spec in catalog.specs},
        )
        self.assertNotIn("ollama", {spec.provider_id for spec in catalog.specs})
        self.assertTrue(all(not spec.production_eligible for spec in catalog.specs))

    def test_harness_catalog_worker_eventlog_schemas_and_fixtures_keep_exact_bytes(self) -> None:
        self.assertGreater(len(PROTECTED_SHA256), 10)
        for relative_path, expected_sha256 in PROTECTED_SHA256.items():
            with self.subTest(path=relative_path):
                self.assertEqual(
                    expected_sha256,
                    hashlib.sha256((ROOT / relative_path).read_bytes()).hexdigest(),
                )


if __name__ == "__main__":
    unittest.main()
