"""Private, code-owned provider runtime catalog and execution selection."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass, replace
from urllib.parse import urlsplit
from weakref import ReferenceType, ref

from worldforge.agent_harness_contracts import MAX_SAFE_INTEGER

_ID_RE = re.compile(r"^[a-z][a-z0-9_]{1,63}$")
_LINEAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:+/@-]{0,127}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_CURRENCY_RE = re.compile(r"^[A-Z]{3}$")
_DATA_CLASS_RE = re.compile(r"^[a-z][a-z0-9_]{1,63}$")
_CREDENTIAL_REVISION_RE = re.compile(r"^credential_revision_[a-z2-7]{26}$")
_DNS_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_SPEC_FORMAT = "world-forge.private.provider_runtime_spec"
_CATALOG_FORMAT = "world-forge.private.provider_runtime_catalog"
_SELECTION_FORMAT = "world-forge.private.provider_execution_selection"
_FORMAT_VERSION = 1
_MAX_CATALOG_ENTRIES = 64
_CODE_OWNED_CATALOG_IDENTITIES: dict[
    int,
    tuple[ReferenceType[object], str, tuple[str, ...]],
] = {}
_CODE_OWNED_RESOLUTION_IDENTITIES: dict[
    int,
    tuple[ReferenceType[object], str, str, str],
] = {}


def _retire_registered_identity(
    registry: dict[int, tuple[object, ...]],
    identity: int,
    registered_ref: ReferenceType[object],
) -> None:
    """Retire only the exact weak registration that produced the callback."""

    registered = registry.get(identity)
    if registered is not None and registered[0] is registered_ref:
        del registry[identity]


def _register_catalog_authority(value: ProviderRuntimeCatalog) -> None:
    identity = id(value)

    def retire(registered_ref: ReferenceType[object]) -> None:
        _retire_registered_identity(  # type: ignore[arg-type]
            _CODE_OWNED_CATALOG_IDENTITIES,
            identity,
            registered_ref,
        )

    _CODE_OWNED_CATALOG_IDENTITIES[identity] = (
        ref(value, retire),
        value.catalog_hash,
        tuple(spec.content_hash for spec in value._entries),
    )


def _register_resolution_authority(value: ResolvedProviderExecution) -> None:
    identity = id(value)

    def retire(registered_ref: ReferenceType[object]) -> None:
        _retire_registered_identity(  # type: ignore[arg-type]
            _CODE_OWNED_RESOLUTION_IDENTITIES,
            identity,
            registered_ref,
        )

    _CODE_OWNED_RESOLUTION_IDENTITIES[identity] = (
        ref(value, retire),
        value.catalog_hash,
        value.spec.content_hash,
        value.selection.content_hash,
    )


class ProviderCatalogError(ValueError):
    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


def _canonical(value: object, reason_code: str) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except Exception:
        raise ProviderCatalogError(reason_code) from None


def _hash(value: object, reason_code: str) -> str:
    return hashlib.sha256(_canonical(value, reason_code)).hexdigest()


def _exact_id(value: object, reason_code: str) -> str:
    if type(value) is not str or _ID_RE.fullmatch(value) is None:
        raise ProviderCatalogError(reason_code)
    return value


def _exact_lineage(value: object, reason_code: str) -> str:
    if type(value) is not str or _LINEAGE_RE.fullmatch(value) is None:
        raise ProviderCatalogError(reason_code)
    return value


def _exact_hash(value: object, reason_code: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise ProviderCatalogError(reason_code)
    return value


def _optional_hash(value: object, reason_code: str) -> str | None:
    return None if value is None else _exact_hash(value, reason_code)


def _exact_integer(value: object, reason_code: str, *, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value <= MAX_SAFE_INTEGER:
        raise ProviderCatalogError(reason_code)
    return value


def _optional_integer(value: object, reason_code: str) -> int | None:
    return None if value is None else _exact_integer(value, reason_code)


def _exact_currency(value: object, reason_code: str) -> str | None:
    if value is None:
        return None
    if type(value) is not str or _CURRENCY_RE.fullmatch(value) is None:
        raise ProviderCatalogError(reason_code)
    return value


def _platforms(value: object, reason_code: str) -> tuple[str, ...]:
    if type(value) is not tuple:
        raise ProviderCatalogError(reason_code)
    result = tuple(tuple.__iter__(value))
    if result != ("linux",) or any(type(item) is not str for item in result):
        raise ProviderCatalogError(reason_code)
    return result


def _data_classes(value: object, reason_code: str) -> tuple[str, ...]:
    if type(value) is not tuple or not 1 <= len(value) <= 32:
        raise ProviderCatalogError(reason_code)
    result = tuple(tuple.__iter__(value))
    if (
        any(type(item) is not str or _DATA_CLASS_RE.fullmatch(item) is None for item in result)
        or len(result) != len(set(result))
        or result != tuple(sorted(result, key=lambda item: item.encode("utf-8")))
    ):
        raise ProviderCatalogError(reason_code)
    return result


def _endpoint_origin(value: object, *, network_scope: str, reason_code: str) -> str | None:
    if network_scope == "none":
        if value is not None:
            raise ProviderCatalogError(reason_code)
        return None
    if network_scope == "loopback" and value is None:
        # A code-owned ephemeral local-service lease binds its destination by
        # launch-policy hash; its one-use numeric port does not exist yet when
        # governance freezes the selection.
        return None
    if type(value) is not str or not value or len(value.encode("utf-8")) > 512:
        raise ProviderCatalogError(reason_code)
    try:
        value.encode("ascii")
        parsed = urlsplit(value)
        port = parsed.port
    except (UnicodeError, ValueError):
        raise ProviderCatalogError(reason_code) from None
    if (
        parsed.scheme not in {"http", "https"}
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path != ""
        or parsed.query != ""
        or parsed.fragment != ""
        or parsed.hostname is None
        or port is None
        or not 1 <= port <= 65535
    ):
        raise ProviderCatalogError(reason_code)
    host = parsed.hostname
    if network_scope == "loopback":
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            raise ProviderCatalogError(reason_code) from None
        if not address.is_loopback or str(address) not in {"127.0.0.1", "::1"}:
            raise ProviderCatalogError(reason_code)
        canonical_host = f"[{address}]" if address.version == 6 else str(address)
    else:
        if parsed.scheme != "https" or host != host.lower() or "*" in host:
            raise ProviderCatalogError(reason_code)
        try:
            ipaddress.ip_address(host)
        except ValueError:
            labels = host.split(".")
            if len(labels) < 2 or any(_DNS_LABEL_RE.fullmatch(label) is None for label in labels):
                raise ProviderCatalogError(reason_code) from None
        else:
            raise ProviderCatalogError(reason_code)
        canonical_host = host
    canonical = f"{parsed.scheme}://{canonical_host}:{port}"
    if value != canonical:
        raise ProviderCatalogError(reason_code)
    return canonical


@dataclass(frozen=True, slots=True)
class ProviderRuntimeSpec:
    runtime_id: str
    runtime_revision: int
    runtime_content_hash: str
    provider_id: str
    model_id: str
    model_version: str
    deployment_class: str
    network_scope: str
    endpoint_origin: str | None
    endpoint_policy_hash: str | None
    egress_enforcement_hash: str | None
    telemetry_attestation_hash: str | None
    usage_policy_hash: str
    pricing_policy_hash: str | None
    pricing_currency: str | None
    credential_requirement_hash: str | None
    redirects_disabled: bool
    supported_platforms: tuple[str, ...]
    production_eligible: bool
    content_hash: str

    @classmethod
    def create(
        cls,
        *,
        runtime_id: object,
        runtime_revision: object,
        runtime_content_hash: object,
        provider_id: object,
        model_id: object,
        model_version: object,
        deployment_class: object,
        network_scope: object,
        endpoint_origin: object,
        endpoint_policy_hash: object,
        egress_enforcement_hash: object,
        telemetry_attestation_hash: object,
        usage_policy_hash: object,
        pricing_policy_hash: object,
        pricing_currency: object,
        credential_requirement_hash: object,
        redirects_disabled: object,
        supported_platforms: object,
        production_eligible: object,
    ) -> ProviderRuntimeSpec:
        reason = "provider_runtime_spec_invalid"
        if type(deployment_class) is not str or deployment_class not in {"local", "cloud"}:
            raise ProviderCatalogError(reason)
        if type(network_scope) is not str or network_scope not in {"none", "loopback", "internet"}:
            raise ProviderCatalogError(reason)
        if type(redirects_disabled) is not bool or type(production_eligible) is not bool:
            raise ProviderCatalogError(reason)
        endpoint = _endpoint_origin(
            endpoint_origin,
            network_scope=network_scope,
            reason_code=reason,
        )
        endpoint_hash = _optional_hash(endpoint_policy_hash, reason)
        egress_hash = _optional_hash(egress_enforcement_hash, reason)
        telemetry_hash = _optional_hash(telemetry_attestation_hash, reason)
        usage_hash = _exact_hash(usage_policy_hash, reason)
        pricing_hash = _optional_hash(pricing_policy_hash, reason)
        currency = _exact_currency(pricing_currency, reason)
        credential_hash = _optional_hash(credential_requirement_hash, reason)
        if network_scope == "none":
            valid = (
                deployment_class == "local"
                and endpoint is None
                and endpoint_hash is None
                and telemetry_hash is None
                and (pricing_hash is None) == (currency is None)
                and credential_hash is None
                and redirects_disabled
            )
        elif network_scope == "loopback":
            valid = (
                deployment_class == "local"
                and endpoint_hash is not None
                and egress_hash is not None
                and telemetry_hash is not None
                and (pricing_hash is None) == (currency is None)
                and redirects_disabled
            )
        else:
            valid = (
                deployment_class == "cloud"
                and endpoint is not None
                and endpoint_hash is not None
                and egress_hash is not None
                and telemetry_hash is not None
                and pricing_hash is not None
                and currency is not None
                and credential_hash is not None
                and redirects_disabled
            )
        if not valid:
            raise ProviderCatalogError(reason)
        values: dict[str, object] = {
            "runtime_id": _exact_id(runtime_id, reason),
            "runtime_revision": _exact_integer(runtime_revision, reason, minimum=1),
            "runtime_content_hash": _exact_hash(runtime_content_hash, reason),
            "provider_id": _exact_id(provider_id, reason),
            "model_id": _exact_lineage(model_id, reason),
            "model_version": _exact_lineage(model_version, reason),
            "deployment_class": deployment_class,
            "network_scope": network_scope,
            "endpoint_origin": endpoint,
            "endpoint_policy_hash": endpoint_hash,
            "egress_enforcement_hash": egress_hash,
            "telemetry_attestation_hash": telemetry_hash,
            "usage_policy_hash": usage_hash,
            "pricing_policy_hash": pricing_hash,
            "pricing_currency": currency,
            "credential_requirement_hash": credential_hash,
            "redirects_disabled": redirects_disabled,
            "supported_platforms": _platforms(supported_platforms, reason),
            "production_eligible": production_eligible,
        }
        document = cls._document(values)
        return cls(**values, content_hash=_hash(document, reason))  # type: ignore[arg-type]

    @staticmethod
    def _document(values: dict[str, object]) -> dict[str, object]:
        return {
            "format": _SPEC_FORMAT,
            "format_version": _FORMAT_VERSION,
            **values,
            "supported_platforms": list(values["supported_platforms"]),
        }

    def as_document(self) -> dict[str, object]:
        values = {
            field: getattr(self, field)
            for field in self.__dataclass_fields__
            if field != "content_hash"
        }
        return {**self._document(values), "content_hash": self.content_hash}

    @property
    def runtime_binding(self) -> dict[str, object]:
        return {
            "id": self.runtime_id,
            "revision": self.runtime_revision,
            "content_hash": self.runtime_content_hash,
        }


def _validate_spec(value: object) -> ProviderRuntimeSpec:
    reason = "provider_runtime_spec_invalid"
    if type(value) is not ProviderRuntimeSpec:
        raise ProviderCatalogError(reason)
    recreated = ProviderRuntimeSpec.create(
        **{
            field: getattr(value, field)
            for field in value.__dataclass_fields__
            if field != "content_hash"
        }
    )
    if type(value.content_hash) is not str or value.content_hash != recreated.content_hash:
        raise ProviderCatalogError(reason)
    return recreated


@dataclass(frozen=True, slots=True)
class ProviderExecutionSelection:
    catalog_hash: str
    spec_hash: str
    runtime_id: str
    runtime_revision: int
    runtime_content_hash: str
    non_secret_config_hash: str
    disclosure_plan_hash: str
    disclosed_data_classes: tuple[str, ...]
    base_payload_hash: str
    tool_catalog_hash: str
    max_turns: int
    max_tool_calls: int
    max_total_tokens: int
    max_cost_minor_units: int | None
    currency: str | None
    max_duration_ms: int
    deadline_ms: int | None
    usage_policy_hash: str
    pricing_policy_hash: str | None
    credential_revision_id: str | None
    content_hash: str

    @classmethod
    def create(
        cls,
        *,
        catalog_hash: object,
        spec_hash: object,
        runtime_id: object,
        runtime_revision: object,
        runtime_content_hash: object,
        non_secret_config_hash: object,
        disclosure_plan_hash: object,
        disclosed_data_classes: object,
        base_payload_hash: object,
        tool_catalog_hash: object,
        max_turns: object,
        max_tool_calls: object,
        max_total_tokens: object,
        max_cost_minor_units: object,
        currency: object,
        max_duration_ms: object,
        deadline_ms: object,
        usage_policy_hash: object,
        pricing_policy_hash: object,
        credential_revision_id: object,
    ) -> ProviderExecutionSelection:
        reason = "provider_execution_selection_invalid"
        cost = _optional_integer(max_cost_minor_units, reason)
        checked_currency = _exact_currency(currency, reason)
        pricing_hash = _optional_hash(pricing_policy_hash, reason)
        if checked_currency is None and (cost is not None or pricing_hash is not None):
            raise ProviderCatalogError(reason)
        if checked_currency is not None and cost is None and pricing_hash is None:
            raise ProviderCatalogError(reason)
        credential_revision = credential_revision_id
        if credential_revision is not None and (
            type(credential_revision) is not str
            or _CREDENTIAL_REVISION_RE.fullmatch(credential_revision) is None
        ):
            raise ProviderCatalogError(reason)
        values: dict[str, object] = {
            "catalog_hash": _exact_hash(catalog_hash, reason),
            "spec_hash": _exact_hash(spec_hash, reason),
            "runtime_id": _exact_id(runtime_id, reason),
            "runtime_revision": _exact_integer(runtime_revision, reason, minimum=1),
            "runtime_content_hash": _exact_hash(runtime_content_hash, reason),
            "non_secret_config_hash": _exact_hash(non_secret_config_hash, reason),
            "disclosure_plan_hash": _exact_hash(disclosure_plan_hash, reason),
            "disclosed_data_classes": _data_classes(disclosed_data_classes, reason),
            "base_payload_hash": _exact_hash(base_payload_hash, reason),
            "tool_catalog_hash": _exact_hash(tool_catalog_hash, reason),
            "max_turns": _exact_integer(max_turns, reason, minimum=1),
            "max_tool_calls": _exact_integer(max_tool_calls, reason),
            "max_total_tokens": _exact_integer(max_total_tokens, reason),
            "max_cost_minor_units": cost,
            "currency": checked_currency,
            "max_duration_ms": _exact_integer(max_duration_ms, reason),
            "deadline_ms": _optional_integer(deadline_ms, reason),
            "usage_policy_hash": _exact_hash(usage_policy_hash, reason),
            "pricing_policy_hash": pricing_hash,
            "credential_revision_id": credential_revision,
        }
        if values["max_turns"] > 64 or values["max_tool_calls"] > 128:
            raise ProviderCatalogError(reason)
        document = cls._document(values)
        return cls(**values, content_hash=_hash(document, reason))  # type: ignore[arg-type]

    @staticmethod
    def _document(values: dict[str, object]) -> dict[str, object]:
        return {
            "format": _SELECTION_FORMAT,
            "format_version": _FORMAT_VERSION,
            **values,
            "disclosed_data_classes": list(values["disclosed_data_classes"]),
        }

    def as_document(self) -> dict[str, object]:
        values = {
            field: getattr(self, field)
            for field in self.__dataclass_fields__
            if field != "content_hash"
        }
        return {**self._document(values), "content_hash": self.content_hash}


def _validate_selection(value: object) -> ProviderExecutionSelection:
    reason = "provider_execution_selection_invalid"
    if type(value) is not ProviderExecutionSelection:
        raise ProviderCatalogError(reason)
    recreated = ProviderExecutionSelection.create(
        **{
            field: getattr(value, field)
            for field in value.__dataclass_fields__
            if field != "content_hash"
        }
    )
    if type(value.content_hash) is not str or value.content_hash != recreated.content_hash:
        raise ProviderCatalogError(reason)
    return recreated


@dataclass(frozen=True, slots=True, weakref_slot=True)
class ResolvedProviderExecution:
    catalog_hash: str
    spec: ProviderRuntimeSpec
    selection: ProviderExecutionSelection

    @property
    def runtime_binding(self) -> dict[str, object]:
        return self.spec.runtime_binding


def _has_resolution_authority(value: ResolvedProviderExecution) -> bool:
    if type(value) is not ResolvedProviderExecution:
        return False
    registered = _CODE_OWNED_RESOLUTION_IDENTITIES.get(id(value))
    return (
        registered is not None
        and registered[0]() is value
        and registered[1] == value.catalog_hash
        and registered[2] == value.spec.content_hash
        and registered[3] == value.selection.content_hash
    )


def _validate_resolved(value: object) -> ResolvedProviderExecution:
    if type(value) is not ResolvedProviderExecution:
        raise ProviderCatalogError("provider_execution_selection_invalid")
    spec = _validate_spec(value.spec)
    selection = _validate_selection(value.selection)
    if (
        type(value.catalog_hash) is not str
        or _SHA256_RE.fullmatch(value.catalog_hash) is None
        or selection.catalog_hash != value.catalog_hash
        or selection.spec_hash != spec.content_hash
        or selection.runtime_id != spec.runtime_id
        or selection.runtime_revision != spec.runtime_revision
        or selection.runtime_content_hash != spec.runtime_content_hash
        or selection.usage_policy_hash != spec.usage_policy_hash
        or selection.pricing_policy_hash != spec.pricing_policy_hash
        or spec.pricing_policy_hash is not None
        and selection.currency != spec.pricing_currency
        or (spec.credential_requirement_hash is None) != (selection.credential_revision_id is None)
    ):
        raise ProviderCatalogError("provider_execution_selection_invalid")
    authoritative = _has_resolution_authority(value)
    checked = ResolvedProviderExecution(
        value.catalog_hash,
        spec,
        selection,
    )
    if authoritative:
        _register_resolution_authority(checked)
    return checked


def _validate_authoritative_resolved(value: object) -> ResolvedProviderExecution:
    checked = _validate_resolved(value)
    if not _has_resolution_authority(checked):
        raise ProviderCatalogError("provider_execution_selection_invalid")
    return checked


def _reject_production_catalog_specs(
    specs: tuple[object, ...],
    *,
    invalid_reason: str,
) -> None:
    for spec in specs:
        if type(spec) is ProviderRuntimeSpec:
            try:
                production_eligible = object.__getattribute__(
                    spec,
                    "production_eligible",
                )
            except Exception:
                raise ProviderCatalogError(invalid_reason) from None
            if production_eligible is True:
                raise ProviderCatalogError("provider_runtime_unavailable")


@dataclass(frozen=True, slots=True, weakref_slot=True)
class ProviderRuntimeCatalog:
    _entries: tuple[ProviderRuntimeSpec, ...]
    catalog_hash: str

    @classmethod
    def create(cls, specs: object) -> ProviderRuntimeCatalog:
        reason = "provider_catalog_invalid"
        if type(specs) is not tuple or not 1 <= len(specs) <= _MAX_CATALOG_ENTRIES:
            raise ProviderCatalogError(reason)
        supplied = tuple(tuple.__iter__(specs))
        _reject_production_catalog_specs(supplied, invalid_reason=reason)
        try:
            checked = tuple(_validate_spec(spec) for spec in supplied)
        except ProviderCatalogError:
            raise
        except Exception:
            raise ProviderCatalogError(reason) from None
        if any(spec.production_eligible or spec.network_scope == "internet" for spec in checked):
            raise ProviderCatalogError("provider_runtime_unavailable")
        try:
            from .pricing import validate_code_owned_pricing_binding

            for spec in checked:
                validate_code_owned_pricing_binding(
                    runtime_id=spec.runtime_id,
                    runtime_revision=spec.runtime_revision,
                    runtime_content_hash=spec.runtime_content_hash,
                    usage_policy_hash=spec.usage_policy_hash,
                    pricing_policy_hash=spec.pricing_policy_hash,
                    pricing_currency=spec.pricing_currency,
                )
        except ProviderCatalogError:
            raise
        except Exception:
            raise ProviderCatalogError("provider_pricing_policy_invalid") from None
        ordered = tuple(
            sorted(
                checked,
                key=lambda spec: (
                    spec.runtime_id.encode("utf-8"),
                    spec.runtime_revision,
                    spec.runtime_content_hash,
                ),
            )
        )
        identities = tuple(
            (spec.runtime_id, spec.runtime_revision, spec.runtime_content_hash) for spec in ordered
        )
        if len(identities) != len(set(identities)):
            raise ProviderCatalogError("provider_catalog_duplicate")
        document = {
            "format": _CATALOG_FORMAT,
            "format_version": _FORMAT_VERSION,
            "specs": [spec.as_document() for spec in ordered],
        }
        return cls(tuple(replace(spec) for spec in ordered), _hash(document, reason))

    @property
    def specs(self) -> tuple[ProviderRuntimeSpec, ...]:
        if type(self._entries) is not tuple:
            raise ProviderCatalogError("provider_catalog_invalid")
        try:
            supplied = tuple(tuple.__iter__(self._entries))
            _reject_production_catalog_specs(
                supplied,
                invalid_reason="provider_catalog_invalid",
            )
            return tuple(replace(_validate_spec(spec)) for spec in supplied)
        except ProviderCatalogError:
            raise
        except Exception:
            raise ProviderCatalogError("provider_catalog_invalid") from None

    def snapshot(self) -> ProviderRuntimeCatalog:
        authoritative = _has_catalog_authority(self)
        entries = self.specs
        snapshot = ProviderRuntimeCatalog.create(entries)
        if (
            type(self.catalog_hash) is not str
            or self.catalog_hash != snapshot.catalog_hash
            or tuple(spec.content_hash for spec in entries)
            != tuple(spec.content_hash for spec in snapshot._entries)
        ):
            raise ProviderCatalogError("provider_catalog_invalid")
        if authoritative:
            _register_catalog_authority(snapshot)
        return snapshot

    def resolve(self, selection: object) -> ResolvedProviderExecution:
        catalog = self.snapshot()
        selected = _validate_selection(selection)
        if selected.catalog_hash != catalog.catalog_hash:
            raise ProviderCatalogError("provider_catalog_mismatch")
        matches = tuple(
            spec
            for spec in catalog._entries
            if (
                spec.runtime_id == selected.runtime_id
                and spec.runtime_revision == selected.runtime_revision
                and spec.runtime_content_hash == selected.runtime_content_hash
            )
        )
        if len(matches) != 1:
            raise ProviderCatalogError("provider_runtime_unavailable")
        resolved = _validate_resolved(
            ResolvedProviderExecution(
                catalog.catalog_hash,
                replace(matches[0]),
                selected,
            )
        )
        if _has_catalog_authority(catalog):
            _register_resolution_authority(resolved)
        return resolved


def _has_catalog_authority(value: ProviderRuntimeCatalog) -> bool:
    if type(value) is not ProviderRuntimeCatalog:
        return False
    registered = _CODE_OWNED_CATALOG_IDENTITIES.get(id(value))
    try:
        entries = object.__getattribute__(value, "_entries")
    except Exception:
        return False
    return (
        registered is not None
        and registered[0]() is value
        and registered[1] == value.catalog_hash
        and registered[2] == tuple(spec.content_hash for spec in entries)
    )


def _create_code_owned_provider_catalog(
    *,
    gateway_policy: object = None,
    local_service_policy: object = None,
) -> ProviderRuntimeCatalog:
    """Build and register only the closed construction-owned runtime catalog."""

    try:
        from .worker_registry import _code_owned_provider_specs

        specs = _code_owned_provider_specs(
            gateway_policy=gateway_policy,
            local_service_policy=local_service_policy,
        )
        catalog = ProviderRuntimeCatalog.create(specs)
    except ProviderCatalogError:
        raise
    except Exception:
        raise ProviderCatalogError("provider_catalog_invalid") from None
    _register_catalog_authority(catalog)
    return catalog


def _validate_authoritative_provider_catalog(value: object) -> ProviderRuntimeCatalog:
    if type(value) is not ProviderRuntimeCatalog or not _has_catalog_authority(value):
        raise ProviderCatalogError("provider_catalog_invalid")
    checked = value.snapshot()
    if not _has_catalog_authority(checked):
        raise ProviderCatalogError("provider_catalog_invalid")
    return checked


__all__ = (
    "ProviderCatalogError",
    "ProviderExecutionSelection",
    "ProviderRuntimeCatalog",
    "ProviderRuntimeSpec",
    "ResolvedProviderExecution",
)
