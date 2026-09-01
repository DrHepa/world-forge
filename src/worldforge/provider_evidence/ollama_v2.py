"""Pure correction-policy contracts for observed Ollama evidence v2.

This module validates supplied bytes and JSON-compatible values only.  It owns
no host, process, service, socket, model, provider, or Studio authority.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from dataclasses import dataclass

ADR0046_RAW_SHA256 = "bc4117aa580834984b4847ddb3a81180c6b14f99ba7954f1959abba8f27fbf42"
ADR0046_VOCABULARY_REGISTRY_SHA256 = (
    "518cdc4056f8d4ad3cfa9a28b08dcf2324c4b3833f4bc04fd49a9e8b2bc06ed9"
)
ADR0046_VOCABULARY_ENTRY_COUNT = 86
FORBIDDEN_V1_CUSTODY_HANDOFF_ALIAS = "worldforge_ollama_evidence_custody_handoff_v1"
V1_DISPOSITION_FORMAT = "world-forge.private.ollama_adr0046_disposition"
CORRECTED_EVIDENCE_FOUNDATION_POLICY_FORMAT = (
    "world-forge.private.ollama_observed_evidence_foundation_policy"
)
FORMAT_VERSION = 2
POLICY_GENERATION = 1
MAX_DOCUMENT_BYTES = 64 * 1024
MAX_JSON_DEPTH = 32
MAX_SAFE_INTEGER = 9_007_199_254_740_991

ADR0046_VOCABULARY_IDS = (
    "worldforge_ollama_installation_observation_v1",
    "worldforge_ollama_model_lock_v1",
    "worldforge_ollama_cloud_off_candidate_v1",
    "worldforge_ollama_evidence_controller_plan_v1",
    "worldforge_ollama_evidence_scenario_plan_v1",
    "worldforge_ollama_evidence_systemd_policy_v1",
    "worldforge_ollama_operation_lease_policy_v1",
    "worldforge_ollama_systemd_unit_recipe_v1",
    "worldforge_ollama_native_process_recipe_v1",
    "worldforge_ollama_candidate_subgroup_recipe_v1",
    "worldforge_ollama_candidate_recipe_policy_v1",
    "worldforge_ollama_candidate_recipe_v1",
    "worldforge_ollama_evidence_authorization_v1",
    "worldforge_ollama_evidence_custody_policy_v1",
    "worldforge_ollama_evidence_custody_proof_v1",
    "worldforge_ollama_evidence_operation_lease_v1",
    "worldforge_ollama_evidence_custody_handoff_offer_v1",
    "worldforge_ollama_evidence_custody_handoff_acceptance_v1",
    "worldforge_ollama_handoff_key_acceptance_v1",
    "worldforge_ollama_evidence_execution_owner_v1",
    "worldforge_ollama_studio_transition_event_payload_v1",
    "worldforge_ollama_transition_target_body_v1",
    "worldforge_ollama_owner_cutoff_v1",
    "worldforge_ollama_recovery_fence_document_v1",
    "worldforge_ollama_evidence_candidate_release_v1",
    "worldforge_ollama_release_gate_snapshot_v1",
    "worldforge_ollama_release_gate_snapshot_acceptance_v1",
    "worldforge_ollama_candidate_configuration_offer_v1",
    "worldforge_ollama_candidate_configuration_acceptance_v1",
    "worldforge_ollama_candidate_configuration_payload_v1",
    "worldforge_ollama_broker_operation_result_v1",
    "worldforge_ollama_broker_result_payload_v1",
    "worldforge_ollama_broker_terminal_v1",
    "worldforge_ollama_broker_control_ack_v1",
    "worldforge_ollama_fork_safe_launcher_v1",
    "worldforge_ollama_fork_window_observation_v1",
    "worldforge_ollama_launcher_procfs_mount_identity_v1",
    "worldforge_ollama_launcher_proc_fd_directory_identity_v1",
    "worldforge_ollama_native_single_thread_broker_policy_v1",
    "worldforge_ollama_native_single_thread_broker_v1",
    "worldforge_ollama_broker_ready_v1",
    "worldforge_ollama_listener_observation_v1",
    "worldforge_ollama_deadline_tombstone_key_document_v1",
    "worldforge_ollama_evidence_deadline_fired_v1",
    "worldforge_ollama_evidence_deadline_action_lifecycle_v1",
    "worldforge_ollama_deadline_action_reboot_abandonment_v1",
    "worldforge_ollama_deadline_action_store_capability_v1",
    "worldforge_ollama_deadline_action_capability_registration_v1",
    "worldforge_ollama_deadline_credential_source_v1",
    "worldforge_ollama_deadline_credential_file_observation_v1",
    "worldforge_ollama_deadline_action_load_recipe_v1",
    "worldforge_ollama_deadline_credential_cleanup_proof_v1",
    "worldforge_ollama_deadline_action_static_install_v1",
    "worldforge_ollama_timer_clock_observation_v1",
    "worldforge_ollama_operation_effect_timing_v1",
    "worldforge_ollama_manager_effect_result_v1",
    "worldforge_ollama_evidence_launch_lock_v1",
    "worldforge_ollama_evidence_handoff_chain_v1",
    "worldforge_ollama_private_evidence_artifact_v1",
    "worldforge_ollama_evidence_limits_v1",
    "worldforge_ollama_evidence_access_policy_v1",
    "worldforge_ollama_ambient_sink_catalog_v1",
    "worldforge_ollama_evidence_consumed_no_resources_v1",
    "worldforge_ollama_evidence_opening_v1",
    "worldforge_ollama_evidence_open_v1",
    "worldforge_ollama_evidence_final_clean_v1",
    "worldforge_ollama_evidence_failed_clean_v1",
    "worldforge_ollama_evidence_failed_cleanup_pending_v1",
    "worldforge_ollama_evidence_recovery_v1",
    "worldforge_ollama_evidence_systemd_terminal_v1",
    "worldforge_ollama_evidence_cleanup_proof_v1",
    "worldforge_ollama_evidence_device_cleanup_v1",
    "worldforge_ollama_evidence_zero_allocation_journal_v1",
    "worldforge_ollama_manager_transaction_rejection_v1",
    "worldforge_ollama_boot_transition_owner_death_proof_v1",
    "worldforge_ollama_reboot_abort_no_evidence_v1",
    "worldforge_ollama_http_wire_buffer_observation_v1",
    "worldforge_ollama_native_wire_parser_policy_v1",
    "worldforge_ollama_native_wire_parser_observation_v1",
    "worldforge_ollama_protocol_text_evidence_v1",
    "worldforge_ollama_control_pre_send_evidence_v1",
    "worldforge_ollama_control_post_send_evidence_v1",
    "worldforge_ollama_scenario_evidence_v1",
    "worldforge_ollama_evidence_envelope_v1",
    "worldforge_ollama_evidence_eligibility_abandonment_v1",
    "worldforge_ollama_private_evidence_artifact_payload_v1",
)

V1_DEFECT_CODES = (
    "ambient_model_root_custody_unsealed",
    "ambient_release_root_custody_unsealed",
    "nss_supplementary_groups_not_excluded",
    "transient_standard_input_fd_setter_unavailable",
)

_VOCABULARY_HEADER = "| Document | Exact ID | Hash authority |"
_VOCABULARY_SEPARATOR = "|---|---|---|"
_VOCABULARY_TERMINATOR = "This vocabulary contains exactly 86 rows"
_VOCABULARY_ROW_RE = re.compile(r"^\|[^|\n]+\| `([^`\n]+)` \|[^|\n]+\|$")
_V1_ID_RE = re.compile(r"^worldforge_ollama_[a-z0-9_]+_v1$")


class OllamaEvidenceContractError(ValueError):
    """Raised when one closed correction-policy input fails validation."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


@dataclass(frozen=True, slots=True)
class ADR0046VocabularyBinding:
    source_sha256: str
    registry_sha256: str
    vocabulary_ids: tuple[str, ...]


def _fail(reason_code: str) -> None:
    raise OllamaEvidenceContractError(reason_code)


def vocabulary_registry_sha256(identifiers: object) -> str:
    """Hash an ordered v1 registry as one LF-terminated sequence of exact IDs."""

    if type(identifiers) is not tuple:
        _fail("adr0046_vocabulary_invalid")
    values = tuple(tuple.__iter__(identifiers))
    if (
        not values
        or any(
            type(identifier) is not str or _V1_ID_RE.fullmatch(identifier) is None
            for identifier in values
        )
    ):
        _fail("adr0046_vocabulary_invalid")
    return hashlib.sha256(("\n".join(values) + "\n").encode("ascii")).hexdigest()


def extract_adr0046_vocabulary_ids(source: object) -> tuple[str, ...]:
    """Extract only the exact vocabulary table, never whole-document aliases."""

    if type(source) is not bytes:
        _fail("adr0046_vocabulary_invalid")
    try:
        text = source.decode("utf-8")
    except UnicodeError:
        _fail("adr0046_vocabulary_invalid")
    if text.count(_VOCABULARY_HEADER) != 1:
        _fail("adr0046_vocabulary_invalid")
    remainder = text.split(_VOCABULARY_HEADER, 1)[1]
    if remainder.count(_VOCABULARY_TERMINATOR) != 1:
        _fail("adr0046_vocabulary_invalid")
    table = remainder.split(_VOCABULARY_TERMINATOR, 1)[0]
    identifiers: list[str] = []
    saw_separator = False
    for line in table.splitlines():
        if not line:
            continue
        if line == _VOCABULARY_SEPARATOR:
            if saw_separator or identifiers:
                _fail("adr0046_vocabulary_invalid")
            saw_separator = True
            continue
        match = _VOCABULARY_ROW_RE.fullmatch(line)
        if match is None or not saw_separator:
            _fail("adr0046_vocabulary_invalid")
        identifiers.append(match.group(1))
    if not saw_separator:
        _fail("adr0046_vocabulary_invalid")
    return tuple(identifiers)


def validate_adr0046_source(source: object) -> ADR0046VocabularyBinding:
    """Validate both the immutable ADR bytes and its isolated ordered registry."""

    identifiers = extract_adr0046_vocabulary_ids(source)
    registry_sha256 = vocabulary_registry_sha256(identifiers)
    if (
        len(identifiers) != ADR0046_VOCABULARY_ENTRY_COUNT
        or identifiers != ADR0046_VOCABULARY_IDS
        or len(set(identifiers)) != len(identifiers)
        or FORBIDDEN_V1_CUSTODY_HANDOFF_ALIAS in identifiers
        or registry_sha256 != ADR0046_VOCABULARY_REGISTRY_SHA256
    ):
        _fail("adr0046_vocabulary_invalid")
    source_sha256 = hashlib.sha256(source).hexdigest()
    if source_sha256 != ADR0046_RAW_SHA256:
        _fail("adr0046_source_invalid")
    return ADR0046VocabularyBinding(
        source_sha256=source_sha256,
        registry_sha256=registry_sha256,
        vocabulary_ids=identifiers,
    )


def _copy_json(value: object, *, depth: int = 1, active: set[int] | None = None) -> object:
    if active is None:
        active = set()
    if depth > MAX_JSON_DEPTH:
        _fail("ollama_v2_document_invalid")
    if type(value) is dict:
        identity = id(value)
        if identity in active:
            _fail("ollama_v2_document_invalid")
        active.add(identity)
        try:
            result: dict[str, object] = {}
            for key, item in dict.items(value):
                if type(key) is not str:
                    _fail("ollama_v2_document_invalid")
                result[key] = _copy_json(item, depth=depth + 1, active=active)
            return result
        finally:
            active.remove(identity)
    if type(value) is list:
        identity = id(value)
        if identity in active:
            _fail("ollama_v2_document_invalid")
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
    _fail("ollama_v2_document_invalid")


def canonical_ollama_evidence_bytes(value: object) -> bytes:
    """Serialize one JSON-only value as compact UTF-8 canonical bytes."""

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
        _fail("ollama_v2_document_invalid")
    if len(encoded) > MAX_DOCUMENT_BYTES:
        _fail("ollama_v2_document_invalid")
    return encoded


def canonical_ollama_evidence_hash(value: object) -> str:
    """Hash a closed document with only its outer content hash omitted."""

    checked = _copy_json(value)
    if type(checked) is not dict:
        _fail("ollama_v2_document_invalid")
    checked.pop("content_hash", None)
    return hashlib.sha256(canonical_ollama_evidence_bytes(checked)).hexdigest()


def _seal(payload: dict[str, object]) -> dict[str, object]:
    result = copy.deepcopy(payload)
    result["content_hash"] = canonical_ollama_evidence_hash(result)
    return result


_V1_DISPOSITION_DOCUMENT = _seal(
    {
        "format": V1_DISPOSITION_FORMAT,
        "format_version": FORMAT_VERSION,
        "policy_generation": POLICY_GENERATION,
        "source_adr": {
            "id": "ADR-0046",
            "sha256": ADR0046_RAW_SHA256,
            "vocabulary_registry_sha256": ADR0046_VOCABULARY_REGISTRY_SHA256,
            "vocabulary_entry_count": ADR0046_VOCABULARY_ENTRY_COUNT,
            "vocabulary_ids": list(ADR0046_VOCABULARY_IDS),
        },
        "disposition": {
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
        "defect_codes": list(V1_DEFECT_CODES),
    }
)

_CORRECTED_EVIDENCE_FOUNDATION_POLICY_DOCUMENT = _seal(
    {
        "format": CORRECTED_EVIDENCE_FOUNDATION_POLICY_FORMAT,
        "format_version": FORMAT_VERSION,
        "policy_generation": POLICY_GENERATION,
        "supersedes": {
            "format": V1_DISPOSITION_FORMAT,
            "content_hash": _V1_DISPOSITION_DOCUMENT["content_hash"],
        },
        "implementation_state": {
            "availability": "unavailable",
            "production_eligible": False,
            "catalog_admission_allowed": False,
            "provider_execution_allowed": False,
            "provider_turn_allowed": False,
            "replay_claim_allowed": False,
            "pricing_claim_allowed": False,
        },
        "principal": {
            "account": "worldforge-ollama-evidence",
            "primary_group": "worldforge-ollama-evidence",
            "dedicated_non_login": True,
            "ambient_account_allowed": False,
            "ambient_ollama_allowed": False,
            "supplementary_groups": [],
            "nss_supplementary_groups_allowed": False,
            "forbidden_group_names": ["render", "video"],
        },
        "release_custody": {
            "custody_kind": "copied_sealed_worldforge_root",
            "ambient_root_allowed": False,
            "final_root_symlink_allowed": False,
            "final_root_hardlink_allowed": False,
            "final_root_writable_allowed": False,
            "byte_manifest_required": True,
        },
        "model_custody": {
            "custody_kind": "copied_sealed_worldforge_root",
            "ambient_root_allowed": False,
            "final_root_symlink_allowed": False,
            "final_root_hardlink_allowed": False,
            "final_root_writable_allowed": False,
            "byte_manifest_required": True,
        },
        "systemd_socket_activation": {
            "installation_mode": "installed_units",
            "socket_unit": "worldforge-ollama-evidence.socket",
            "service_unit": "worldforge-ollama-evidence.service",
            "file_descriptor_name": "ollama-http",
            "standard_input": "fd:ollama-http",
            "descriptor_name_match_required": True,
            "transient_fd_setter_allowed": False,
        },
        "cloud_network": {
            "ollama_no_cloud": "1",
            "environment_inheritance_allowed": False,
            "listen_host": "127.0.0.1",
            "listen_scope": "numeric_ipv4_loopback_only",
            "dns_allowed": False,
            "non_loopback_allowed": False,
            "proxy_allowed": False,
            "proxy_environment_inheritance_allowed": False,
            "proxy_environment_names": [
                "ALL_PROXY",
                "FTP_PROXY",
                "HTTPS_PROXY",
                "HTTP_PROXY",
                "NO_PROXY",
                "all_proxy",
                "ftp_proxy",
                "http_proxy",
                "https_proxy",
                "no_proxy",
            ],
            "redirects_allowed": False,
        },
        "device_boundary": {
            "profile": "cpu_only_no_accelerator",
            "supplementary_accelerator_groups": [],
            "device_allow_entries": [],
            "accelerator_device_paths": [],
            "accelerator_backends": [],
            "accelerator_runtime_allowed": False,
            "accelerator_device_open_allowed": False,
            "accelerator_device_mmap_allowed": False,
            "accelerator_device_ioctl_allowed": False,
        },
    }
)


def canonical_v1_disposition_document() -> dict[str, object]:
    """Return the immutable ADR-0046/v1 permanent-unavailability document."""

    return copy.deepcopy(_V1_DISPOSITION_DOCUMENT)


def canonical_corrected_evidence_foundation_policy_document() -> dict[str, object]:
    """Return the immutable v2 corrected evidence foundation policy."""

    return copy.deepcopy(_CORRECTED_EVIDENCE_FOUNDATION_POLICY_DOCUMENT)


def _validate_exact_document(
    value: object,
    expected: dict[str, object],
    *,
    expected_format: str,
) -> dict[str, object]:
    checked = _copy_json(value)
    if type(checked) is not dict or checked.get("format") != expected_format:
        _fail("ollama_v2_format_unsupported")
    declared_hash = checked.get("content_hash")
    if (
        type(declared_hash) is not str
        or re.fullmatch(r"[0-9a-f]{64}", declared_hash) is None
        or canonical_ollama_evidence_hash(checked) != declared_hash
        or canonical_ollama_evidence_bytes(checked) != canonical_ollama_evidence_bytes(expected)
    ):
        _fail("ollama_v2_document_invalid")
    return copy.deepcopy(checked)


def validate_v1_disposition_document(value: object) -> dict[str, object]:
    """Validate only the exact immutable v1 disposition document."""

    return _validate_exact_document(
        value,
        _V1_DISPOSITION_DOCUMENT,
        expected_format=V1_DISPOSITION_FORMAT,
    )


def validate_corrected_evidence_foundation_policy_document(
    value: object,
) -> dict[str, object]:
    """Validate only the exact immutable corrected v2 foundation policy."""

    return _validate_exact_document(
        value,
        _CORRECTED_EVIDENCE_FOUNDATION_POLICY_DOCUMENT,
        expected_format=CORRECTED_EVIDENCE_FOUNDATION_POLICY_FORMAT,
    )


def validate_ollama_evidence_document(
    value: object,
    *,
    expected_format: object = None,
) -> dict[str, object]:
    """Dispatch one exact correction-policy document by its closed format."""

    if expected_format is not None:
        if type(expected_format) is not str or expected_format not in {
            V1_DISPOSITION_FORMAT,
            CORRECTED_EVIDENCE_FOUNDATION_POLICY_FORMAT,
        }:
            _fail("ollama_v2_format_unsupported")
    checked = _copy_json(value)
    if type(checked) is not dict or type(checked.get("format")) is not str:
        _fail("ollama_v2_format_unsupported")
    format_name = checked["format"]
    if expected_format is not None and format_name != expected_format:
        _fail("ollama_v2_format_unsupported")
    if format_name == V1_DISPOSITION_FORMAT:
        return validate_v1_disposition_document(checked)
    if format_name == CORRECTED_EVIDENCE_FOUNDATION_POLICY_FORMAT:
        return validate_corrected_evidence_foundation_policy_document(checked)
    _fail("ollama_v2_format_unsupported")


__all__ = (
    "ADR0046_RAW_SHA256",
    "ADR0046_VOCABULARY_ENTRY_COUNT",
    "ADR0046_VOCABULARY_IDS",
    "ADR0046_VOCABULARY_REGISTRY_SHA256",
    "ADR0046VocabularyBinding",
    "CORRECTED_EVIDENCE_FOUNDATION_POLICY_FORMAT",
    "FORBIDDEN_V1_CUSTODY_HANDOFF_ALIAS",
    "FORMAT_VERSION",
    "OllamaEvidenceContractError",
    "POLICY_GENERATION",
    "V1_DEFECT_CODES",
    "V1_DISPOSITION_FORMAT",
    "canonical_corrected_evidence_foundation_policy_document",
    "canonical_ollama_evidence_bytes",
    "canonical_ollama_evidence_hash",
    "canonical_v1_disposition_document",
    "extract_adr0046_vocabulary_ids",
    "validate_adr0046_source",
    "validate_corrected_evidence_foundation_policy_document",
    "validate_ollama_evidence_document",
    "validate_v1_disposition_document",
    "vocabulary_registry_sha256",
)
