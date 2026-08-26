"""Fixed private worker registry for the non-production conformance runtime."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from .provider_catalog import ProviderRuntimeCatalog, ProviderRuntimeSpec
from .worker import (
    _CONFORMANCE_RUNTIME_ID,
    _CONFORMANCE_RUNTIME_REVISION,
    WORKER_BOOTSTRAP_TEMPLATE,
)


@dataclass(frozen=True, slots=True)
class _FixedRuntimeBinding:
    identifier: str
    revision: int
    content_hash: str


_FIXED_RUNTIME_BINDING = _FixedRuntimeBinding(
    identifier=_CONFORMANCE_RUNTIME_ID,
    revision=_CONFORMANCE_RUNTIME_REVISION,
    content_hash=hashlib.sha256(WORKER_BOOTSTRAP_TEMPLATE.encode("utf-8")).hexdigest(),
)

_FIXED_RUNTIME_SPEC = ProviderRuntimeSpec.create(
    runtime_id=_FIXED_RUNTIME_BINDING.identifier,
    runtime_revision=_FIXED_RUNTIME_BINDING.revision,
    runtime_content_hash=_FIXED_RUNTIME_BINDING.content_hash,
    provider_id="worldforge",
    model_id="conformance",
    model_version=str(_FIXED_RUNTIME_BINDING.revision),
    deployment_class="local",
    network_scope="none",
    endpoint_origin=None,
    endpoint_policy_hash=None,
    egress_enforcement_hash=None,
    telemetry_attestation_hash=None,
    pricing_policy_hash=None,
    pricing_currency=None,
    credential_requirement_hash=None,
    redirects_disabled=True,
    supported_platforms=("linux",),
    production_eligible=False,
)
_FIXED_PROVIDER_CATALOG = ProviderRuntimeCatalog.create((_FIXED_RUNTIME_SPEC,))


def _bind_fixed_runtime(binding: _FixedRuntimeBinding):
    def identity() -> dict[str, object]:
        """Return a fresh code-owned identity; callers cannot select a runtime."""

        return {
            "id": binding.identifier,
            "revision": binding.revision,
            "content_hash": binding.content_hash,
        }

    def matches(value: object) -> bool:
        return (
            type(value) is dict
            and set(value) == {"id", "revision", "content_hash"}
            and type(value["id"]) is str
            and value["id"] == binding.identifier
            and type(value["revision"]) is int
            and value["revision"] == binding.revision
            and type(value["content_hash"]) is str
            and value["content_hash"] == binding.content_hash
        )

    return identity, matches


fixed_runtime_identity, _matches_fixed_runtime = _bind_fixed_runtime(_FIXED_RUNTIME_BINDING)
del _bind_fixed_runtime


def fixed_runtime_spec() -> ProviderRuntimeSpec:
    """Return a detached copy of the only code-owned executable descriptor."""

    return _FIXED_PROVIDER_CATALOG.specs[0]


def fixed_provider_catalog() -> ProviderRuntimeCatalog:
    """Return the immutable catalog containing only the conformance runtime."""

    return _FIXED_PROVIDER_CATALOG.snapshot()


__all__ = ("fixed_provider_catalog", "fixed_runtime_identity", "fixed_runtime_spec")
