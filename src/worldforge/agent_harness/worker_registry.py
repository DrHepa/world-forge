"""Fixed private worker registry for the non-production conformance runtime."""

from __future__ import annotations

from .worker import CONFORMANCE_RUNTIME_HASH

CONFORMANCE_RUNTIME_ID = "worldforge.conformance.provider"
CONFORMANCE_RUNTIME_REVISION = 1
CONFORMANCE_RUNTIME: dict[str, object] = {
    "id": CONFORMANCE_RUNTIME_ID,
    "revision": CONFORMANCE_RUNTIME_REVISION,
    "content_hash": CONFORMANCE_RUNTIME_HASH,
}


def fixed_runtime_identity() -> dict[str, object]:
    """Return a fresh code-owned identity; callers cannot select a runtime."""

    return dict(CONFORMANCE_RUNTIME)


__all__ = (
    "CONFORMANCE_RUNTIME",
    "CONFORMANCE_RUNTIME_HASH",
    "CONFORMANCE_RUNTIME_ID",
    "CONFORMANCE_RUNTIME_REVISION",
    "fixed_runtime_identity",
)
