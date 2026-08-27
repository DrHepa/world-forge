"""Closed private registry for exact code-owned provider workers."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass, replace
from enum import Enum

from .loopback_gateway import (
    LoopbackGatewayPolicy,
    code_owned_no_telemetry_branch_hash,
)
from .pricing import (
    _build_code_owned_pricing_policy,
    _build_code_owned_unpriced_runtime_binding,
    _install_code_owned_pricing_policy,
    _install_code_owned_unpriced_runtime_binding,
)
from .provider_catalog import (
    ProviderCatalogError,
    ProviderRuntimeCatalog,
    ProviderRuntimeSpec,
    _create_code_owned_provider_catalog,
)
from .provider_egress import (
    ProviderEgressEnforcementProfile,
    _validate_provider_egress_profile,
    provider_egress_enforcement_profile,
)
from .usage import code_owned_usage_policy_hash
from .worker import (
    RUNTIME_CONTENT_HASH_TOKEN,
    _conformance_worker_artifact,
    _deterministic_probe_worker_artifact,
    _WorkerArtifact,
)

_REGISTRY_ERROR = "code_owned_runtime_registry_invalid"
_PROTOCOL_VERSION = 3
_ENVIRONMENT_PROFILE = (
    ("ANTHROPIC_DISABLE_TELEMETRY", "1"),
    ("DO_NOT_TRACK", "1"),
    ("HF_HUB_DISABLE_TELEMETRY", "1"),
    ("OPENAI_DISABLE_TELEMETRY", "1"),
    ("PYTHONDONTWRITEBYTECODE", "1"),
    ("PYTHONIOENCODING", "utf-8"),
    ("PYTHONUTF8", "1"),
)


class _CodeOwnedRuntimeKey(Enum):
    CONFORMANCE = "conformance"
    DETERMINISTIC_PROBE = "deterministic_probe"


@dataclass(frozen=True, slots=True)
class _CodeOwnedRuntimeEntry:
    key: _CodeOwnedRuntimeKey
    artifact: _WorkerArtifact
    spec: ProviderRuntimeSpec
    environment_profile: tuple[tuple[str, str], ...]
    egress_enforcement: ProviderEgressEnforcementProfile

    @property
    def identifier(self) -> str:
        return self.artifact.identifier

    @property
    def revision(self) -> int:
        return self.artifact.revision

    @property
    def protocol_version(self) -> int:
        return self.artifact.protocol_version

    @property
    def bootstrap_template(self) -> str:
        return self.artifact.bootstrap_template

    @property
    def bootstrap_source(self) -> str:
        return self.artifact.bootstrap_source

    @property
    def content_hash(self) -> str:
        return self.artifact.content_hash

    @property
    def runtime_binding(self) -> dict[str, object]:
        return {
            "id": self.identifier,
            "revision": self.revision,
            "content_hash": self.content_hash,
        }


def _expected_spec(
    key: _CodeOwnedRuntimeKey,
    artifact: _WorkerArtifact,
    egress_enforcement: ProviderEgressEnforcementProfile,
    gateway_policy: LoopbackGatewayPolicy | None = None,
) -> ProviderRuntimeSpec:
    if key is _CodeOwnedRuntimeKey.CONFORMANCE:
        model_id = "conformance"
    elif key is _CodeOwnedRuntimeKey.DETERMINISTIC_PROBE:
        model_id = "deterministic_probe"
    else:
        raise RuntimeError(_REGISTRY_ERROR)
    if gateway_policy is not None:
        if key is not _CodeOwnedRuntimeKey.DETERMINISTIC_PROBE:
            raise RuntimeError(_REGISTRY_ERROR)
        try:
            checked_policy = LoopbackGatewayPolicy.create(gateway_policy.endpoint_origin)
        except Exception:
            raise RuntimeError(_REGISTRY_ERROR) from None
        if (
            gateway_policy != checked_policy
            or gateway_policy.canonical_document != checked_policy.canonical_document
        ):
            raise RuntimeError(_REGISTRY_ERROR)
        network_scope = "loopback"
        endpoint_origin = checked_policy.endpoint_origin
        endpoint_policy_hash = checked_policy.content_hash
        telemetry_attestation_hash = code_owned_no_telemetry_branch_hash()
    else:
        network_scope = "none"
        endpoint_origin = None
        endpoint_policy_hash = None
        telemetry_attestation_hash = None
    usage_policy_hash = code_owned_usage_policy_hash(artifact.identifier)
    pricing_policy = (
        _build_code_owned_pricing_policy(
            runtime_id=artifact.identifier,
            runtime_revision=artifact.revision,
            runtime_content_hash=artifact.content_hash,
            usage_policy_hash=usage_policy_hash,
        )
        if key is _CodeOwnedRuntimeKey.DETERMINISTIC_PROBE
        else None
    )
    return ProviderRuntimeSpec.create(
        runtime_id=artifact.identifier,
        runtime_revision=artifact.revision,
        runtime_content_hash=artifact.content_hash,
        provider_id="worldforge",
        model_id=model_id,
        model_version=str(artifact.revision),
        deployment_class="local",
        network_scope=network_scope,
        endpoint_origin=endpoint_origin,
        endpoint_policy_hash=endpoint_policy_hash,
        egress_enforcement_hash=egress_enforcement.content_hash,
        telemetry_attestation_hash=telemetry_attestation_hash,
        usage_policy_hash=usage_policy_hash,
        pricing_policy_hash=(None if pricing_policy is None else pricing_policy.content_hash),
        pricing_currency=(None if pricing_policy is None else pricing_policy.currency),
        credential_requirement_hash=None,
        redirects_disabled=True,
        supported_platforms=("linux",),
        production_eligible=False,
    )


def _validate_artifact(value: object) -> _WorkerArtifact:
    if type(value) is not _WorkerArtifact:
        raise RuntimeError(_REGISTRY_ERROR)
    if (
        type(value.identifier) is not str
        or type(value.revision) is not int
        or type(value.protocol_version) is not int
        or value.protocol_version != _PROTOCOL_VERSION
        or type(value.bootstrap_template) is not str
        or type(value.bootstrap_source) is not str
        or type(value.content_hash) is not str
        or len(value.content_hash) != 64
        or any(character not in "0123456789abcdef" for character in value.content_hash)
        or value.bootstrap_template.count(RUNTIME_CONTENT_HASH_TOKEN) != 1
        or RUNTIME_CONTENT_HASH_TOKEN in value.bootstrap_source
        or value.bootstrap_source.count(value.content_hash) != 1
        or value.content_hash
        != hashlib.sha256(value.bootstrap_template.encode("utf-8")).hexdigest()
        or value.bootstrap_source
        != value.bootstrap_template.replace(RUNTIME_CONTENT_HASH_TOKEN, value.content_hash)
    ):
        raise RuntimeError(_REGISTRY_ERROR)
    return replace(value)


def _build_entry(
    key: _CodeOwnedRuntimeKey,
    factory: Callable[[], _WorkerArtifact],
) -> _CodeOwnedRuntimeEntry:
    if type(key) is not _CodeOwnedRuntimeKey or not callable(factory):
        raise RuntimeError(_REGISTRY_ERROR)
    try:
        artifact = _validate_artifact(factory())
        egress_enforcement = provider_egress_enforcement_profile()
    except Exception:
        raise RuntimeError(_REGISTRY_ERROR) from None
    return _CodeOwnedRuntimeEntry(
        key=key,
        artifact=artifact,
        spec=_expected_spec(key, artifact, egress_enforcement),
        environment_profile=_ENVIRONMENT_PROFILE,
        egress_enforcement=egress_enforcement,
    )


_RUNTIME_ENTRIES = (
    _build_entry(_CodeOwnedRuntimeKey.CONFORMANCE, _conformance_worker_artifact),
    _build_entry(
        _CodeOwnedRuntimeKey.DETERMINISTIC_PROBE,
        _deterministic_probe_worker_artifact,
    ),
)
_conformance_entry = next(
    entry for entry in _RUNTIME_ENTRIES if entry.key is _CodeOwnedRuntimeKey.CONFORMANCE
)
_install_code_owned_unpriced_runtime_binding(
    _build_code_owned_unpriced_runtime_binding(
        runtime_id=_conformance_entry.identifier,
        runtime_revision=_conformance_entry.revision,
        runtime_content_hash=_conformance_entry.content_hash,
        usage_policy_hash=_conformance_entry.spec.usage_policy_hash,
    )
)
_pricing_entry = next(
    entry for entry in _RUNTIME_ENTRIES if entry.key is _CodeOwnedRuntimeKey.DETERMINISTIC_PROBE
)
_install_code_owned_pricing_policy(
    _build_code_owned_pricing_policy(
        runtime_id=_pricing_entry.identifier,
        runtime_revision=_pricing_entry.revision,
        runtime_content_hash=_pricing_entry.content_hash,
        usage_policy_hash=_pricing_entry.spec.usage_policy_hash,
    )
)
del _conformance_entry
del _pricing_entry
# Factories are construction-only. Runtime command, protocol, and dispatch paths
# retain only the validated immutable artifacts above.
del _conformance_worker_artifact
del _deterministic_probe_worker_artifact

_CANONICAL_ENTRY_SNAPSHOTS = tuple(
    (
        entry.key,
        replace(entry.artifact),
        replace(entry.spec),
        tuple(entry.environment_profile),
        replace(entry.egress_enforcement),
    )
    for entry in _RUNTIME_ENTRIES
)


def _validate_entry(value: object) -> _CodeOwnedRuntimeEntry:
    if type(value) is not _CodeOwnedRuntimeEntry or type(value.key) is not _CodeOwnedRuntimeKey:
        raise RuntimeError(_REGISTRY_ERROR)
    canonical_matches = tuple(
        snapshot for snapshot in _CANONICAL_ENTRY_SNAPSHOTS if snapshot[0] is value.key
    )
    if len(canonical_matches) != 1:
        raise RuntimeError(_REGISTRY_ERROR)
    (
        _canonical_key,
        canonical_artifact,
        canonical_spec,
        canonical_environment,
        canonical_egress_enforcement,
    ) = canonical_matches[0]
    try:
        artifact = _validate_artifact(value.artifact)
        egress_enforcement = _validate_provider_egress_profile(value.egress_enforcement)
        supplied_spec = ProviderRuntimeCatalog.create((value.spec,)).specs[0]
        gateway_policy = None
        if (
            value.key is _CodeOwnedRuntimeKey.DETERMINISTIC_PROBE
            and supplied_spec.network_scope == "loopback"
        ):
            gateway_policy = LoopbackGatewayPolicy.create(supplied_spec.endpoint_origin)
        expected_spec = _expected_spec(
            value.key,
            artifact,
            egress_enforcement,
            gateway_policy,
        )
    except Exception:
        raise RuntimeError(_REGISTRY_ERROR) from None
    if (
        type(value.artifact) is not _WorkerArtifact
        or type(value.environment_profile) is not tuple
        or any(
            type(item) is not tuple or len(item) != 2 or any(type(part) is not str for part in item)
            for item in tuple.__iter__(value.environment_profile)
        )
        or tuple(tuple.__iter__(value.environment_profile)) != _ENVIRONMENT_PROFILE
        or artifact != canonical_artifact
        or gateway_policy is None
        and supplied_spec != canonical_spec
        or tuple(value.environment_profile) != canonical_environment
        or egress_enforcement != canonical_egress_enforcement
        or supplied_spec != expected_spec
        or value.spec != supplied_spec
        or value.runtime_binding != expected_spec.runtime_binding
    ):
        raise RuntimeError(_REGISTRY_ERROR)
    return replace(
        value,
        artifact=replace(artifact),
        spec=replace(expected_spec),
        environment_profile=tuple(value.environment_profile),
        egress_enforcement=replace(egress_enforcement),
    )


def _validated_entries() -> tuple[_CodeOwnedRuntimeEntry, ...]:
    if type(_RUNTIME_ENTRIES) is not tuple:
        raise RuntimeError(_REGISTRY_ERROR)
    supplied = tuple(tuple.__iter__(_RUNTIME_ENTRIES))
    if len(supplied) != len(_CodeOwnedRuntimeKey):
        raise RuntimeError(_REGISTRY_ERROR)
    entries = tuple(_validate_entry(entry) for entry in supplied)
    if (
        tuple(entry.key for entry in entries) != tuple(_CodeOwnedRuntimeKey)
        or len({entry.identifier for entry in entries}) != len(entries)
        or len({entry.content_hash for entry in entries}) != len(entries)
        or len({entry.spec.content_hash for entry in entries}) != len(entries)
    ):
        raise RuntimeError(_REGISTRY_ERROR)
    try:
        catalog = ProviderRuntimeCatalog.create(tuple(entry.spec for entry in entries))
    except ProviderCatalogError:
        raise RuntimeError(_REGISTRY_ERROR) from None
    if catalog.specs != tuple(entry.spec for entry in entries):
        raise RuntimeError(_REGISTRY_ERROR)
    return entries


def runtime_entry(
    key: _CodeOwnedRuntimeKey,
    *,
    gateway_policy: LoopbackGatewayPolicy | None = None,
) -> _CodeOwnedRuntimeEntry:
    """Return a detached validated entry for one internal enum key."""

    if type(key) is not _CodeOwnedRuntimeKey:
        raise RuntimeError(_REGISTRY_ERROR)
    matches = tuple(entry for entry in _validated_entries() if entry.key is key)
    if len(matches) != 1:
        raise RuntimeError(_REGISTRY_ERROR)
    entry = _validate_entry(matches[0])
    if gateway_policy is None:
        return entry
    if key is not _CodeOwnedRuntimeKey.DETERMINISTIC_PROBE:
        raise RuntimeError(_REGISTRY_ERROR)
    return replace(
        entry,
        spec=_expected_spec(key, entry.artifact, entry.egress_enforcement, gateway_policy),
    )


def runtime_identity(
    key: _CodeOwnedRuntimeKey,
    *,
    gateway_policy: LoopbackGatewayPolicy | None = None,
) -> dict[str, object]:
    return runtime_entry(key, gateway_policy=gateway_policy).runtime_binding


def runtime_spec(
    key: _CodeOwnedRuntimeKey,
    *,
    gateway_policy: LoopbackGatewayPolicy | None = None,
) -> ProviderRuntimeSpec:
    return replace(runtime_entry(key, gateway_policy=gateway_policy).spec)


def runtime_artifact(key: _CodeOwnedRuntimeKey) -> _WorkerArtifact:
    return replace(runtime_entry(key).artifact)


def runtime_environment(key: _CodeOwnedRuntimeKey) -> dict[str, str]:
    entry = runtime_entry(key)
    return dict(entry.environment_profile)


def _matches_runtime(key: _CodeOwnedRuntimeKey, value: object) -> bool:
    try:
        expected = runtime_identity(key)
    except RuntimeError:
        return False
    return (
        type(value) is dict
        and set(value) == {"id", "revision", "content_hash"}
        and type(value["id"]) is str
        and type(value["revision"]) is int
        and type(value["content_hash"]) is str
        and value == expected
    )


def _code_owned_provider_specs(
    *,
    gateway_policy: LoopbackGatewayPolicy | None = None,
) -> tuple[ProviderRuntimeSpec, ...]:
    entries = tuple(
        runtime_entry(
            entry.key,
            gateway_policy=(
                gateway_policy if entry.key is _CodeOwnedRuntimeKey.DETERMINISTIC_PROBE else None
            ),
        )
        for entry in _validated_entries()
    )
    return tuple(entry.spec for entry in entries)


def code_owned_provider_catalog(
    *,
    gateway_policy: LoopbackGatewayPolicy | None = None,
) -> ProviderRuntimeCatalog:
    return _create_code_owned_provider_catalog(gateway_policy=gateway_policy)


def runtime_entry_for_selection(
    selection: object,
    *,
    gateway_policy: LoopbackGatewayPolicy | None = None,
) -> _CodeOwnedRuntimeEntry:
    catalog = code_owned_provider_catalog(gateway_policy=gateway_policy)
    resolved = catalog.resolve(selection)
    matches = tuple(
        entry
        for entry in tuple(
            runtime_entry(
                candidate.key,
                gateway_policy=(
                    gateway_policy
                    if candidate.key is _CodeOwnedRuntimeKey.DETERMINISTIC_PROBE
                    else None
                ),
            )
            for candidate in _validated_entries()
        )
        if (
            entry.spec == resolved.spec
            and entry.identifier == resolved.selection.runtime_id
            and entry.revision == resolved.selection.runtime_revision
            and entry.content_hash == resolved.selection.runtime_content_hash
        )
    )
    if len(matches) != 1:
        raise ProviderCatalogError("provider_runtime_unavailable")
    entry = matches[0]
    if gateway_policy is None:
        return _validate_entry(entry)
    return replace(entry)


def fixed_runtime_identity() -> dict[str, object]:
    """Return the historical default conformance identity."""

    return runtime_identity(_CodeOwnedRuntimeKey.CONFORMANCE)


def fixed_runtime_spec() -> ProviderRuntimeSpec:
    """Return the historical default conformance descriptor."""

    return runtime_spec(_CodeOwnedRuntimeKey.CONFORMANCE)


def fixed_provider_catalog() -> ProviderRuntimeCatalog:
    """Compatibility alias for the complete closed code-owned catalog."""

    return code_owned_provider_catalog()


__all__ = (
    "code_owned_provider_catalog",
    "fixed_provider_catalog",
    "fixed_runtime_identity",
    "fixed_runtime_spec",
)
