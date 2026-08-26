"""Fixed private worker registry for the non-production conformance runtime."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

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


__all__ = ("fixed_runtime_identity",)
