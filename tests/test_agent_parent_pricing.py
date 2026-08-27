from __future__ import annotations

import dataclasses
import gc
import hashlib
import json
import tempfile
import unittest
import weakref
from dataclasses import replace
from decimal import Decimal
from pathlib import Path
from unittest import mock

from tests.agent_harness_fakes import FakeCancellation, FakeClock, FakeJournal, FakeProvider
from tests.test_agent_execution_kernel import _documents, _kernel, _request, _usage
from worldforge.agent_harness import (
    AgentEventLog,
    AgentExecutionCoordinator,
    AgentExecutionKernel,
    CapabilityBroker,
)
from worldforge.agent_harness import event_log as event_log_module
from worldforge.agent_harness import pricing as pricing_module
from worldforge.agent_harness import provider_catalog as provider_catalog_module
from worldforge.agent_harness import usage as usage_module
from worldforge.agent_harness import worker_protocol as worker_protocol_module
from worldforge.agent_harness.event_log import AgentEventLogCorrupt, AgentEventLogError
from worldforge.agent_harness.kernel import KernelError
from worldforge.agent_harness.ports import ProviderTurnResult, ProviderUsage
from worldforge.agent_harness.pricing import (
    ExactPricingPolicy,
    PricingAuthorityError,
    calculate_execution_cost,
    canonical_pricing_hash,
    code_owned_pricing_policy,
    resolve_code_owned_pricing_policy,
)
from worldforge.agent_harness.provider_catalog import (
    ProviderCatalogError,
    ProviderExecutionSelection,
    ProviderRuntimeCatalog,
    ProviderRuntimeSpec,
    ResolvedProviderExecution,
)
from worldforge.agent_harness.provider_governance import (
    InMemoryProviderGovernanceAuthority,
    ProviderGovernanceDecision,
)
from worldforge.agent_harness.usage import (
    CostEvidence,
    ProviderAccountingLineage,
    TokenEvidence,
    UsageAccounting,
    UsageEvidenceError,
    build_legacy_usage_accounting,
    canonical_usage_hash,
    code_owned_usage_policy_hash,
    validate_usage_accounting,
)
from worldforge.agent_harness.worker_registry import (
    _CodeOwnedRuntimeKey,
    code_owned_provider_catalog,
    runtime_identity,
    runtime_spec,
)
from worldforge.agent_harness_contracts import MAX_SAFE_INTEGER, canonical_agent_harness_hash

H1 = "1" * 64
H2 = "2" * 64


def _borrow_embedded_authority(
    source: object,
    target: object,
    **changes: object,
) -> object:
    """Reproduce the pre-registry proof theft without depending on its survival."""

    try:
        authority = object.__getattribute__(source, "_authority")
        fields = tuple(authority.__dataclass_fields__)
    except (AttributeError, TypeError):
        return target
    cloned = object.__new__(type(authority))
    for name in fields:
        object.__setattr__(cloned, name, changes.get(name, getattr(authority, name)))
    object.__setattr__(target, "_authority", cloned)
    return target


class _LegacyExecutionJournal:
    """Exact prior-signature journal with no private priced-lineage extension."""

    def __init__(self) -> None:
        self._inner = FakeJournal()

    @property
    def operations(self) -> list[str]:
        return self._inner.operations

    def begin_execution(
        self,
        execution_id: str,
        log_id: str,
        activation: dict[str, object],
        grant: dict[str, object],
        *,
        request_fingerprint: str | None,
    ) -> bool:
        return self._inner.begin_execution(
            execution_id,
            log_id,
            activation,
            grant,
            request_fingerprint=request_fingerprint,
        )

    def append_event(self, *args: object, **kwargs: object) -> None:
        self._inner.append_event(*args, **kwargs)  # type: ignore[arg-type]

    def finalize(self, *args: object, **kwargs: object) -> None:
        self._inner.finalize(*args, **kwargs)  # type: ignore[arg-type]


def _probe_token(value: int) -> TokenEvidence:
    return TokenEvidence.create(
        state="derived",
        source_kind="code_owned_runtime",
        value=value,
        policy_hash=code_owned_usage_policy_hash("worldforge_deterministic_probe_provider"),
    )


def _unavailable_cache() -> TokenEvidence:
    return TokenEvidence.create(
        state="unavailable",
        source_kind="none",
        unavailable_reason="code_owned_policy_absent",
    )


def _unavailable_cost() -> CostEvidence:
    return CostEvidence.create(
        state="unavailable",
        source_kind="none",
        unavailable_reason="parent_pricing_unavailable",
    )


def _probe_usage(*, cost: object | None = None) -> ProviderUsage:
    return ProviderUsage(
        _probe_token(1),
        _probe_token(1),
        _unavailable_cache(),
        _unavailable_cost() if cost is None else cost,  # type: ignore[arg-type]
    )


def _probe_documents() -> tuple[dict[str, object], dict[str, object]]:
    activation, grant = _documents(capabilities=[], tools=[])
    binding = runtime_identity(_CodeOwnedRuntimeKey.DETERMINISTIC_PROBE)
    activation["runtime"] = binding
    activation["content_hash"] = canonical_agent_harness_hash(activation)
    grant["runtime"] = binding
    grant["activation"] = {
        "id": activation["activation_id"],
        "content_hash": activation["content_hash"],
    }
    grant["content_hash"] = canonical_agent_harness_hash(grant)
    return activation, grant


def _json_hash(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def _priced_selection(request, broker: CapabilityBroker) -> ProviderExecutionSelection:
    catalog = code_owned_provider_catalog()
    spec = runtime_spec(_CodeOwnedRuntimeKey.DETERMINISTIC_PROBE)
    tool_catalog = broker.eligible_tool_catalog(
        effective_capabilities=frozenset(request.grant["effective_capability_ids"]),
        effective_tools=frozenset(request.grant["effective_tool_ids"]),
    )
    return ProviderExecutionSelection.create(
        catalog_hash=catalog.catalog_hash,
        spec_hash=spec.content_hash,
        runtime_id=spec.runtime_id,
        runtime_revision=spec.runtime_revision,
        runtime_content_hash=spec.runtime_content_hash,
        non_secret_config_hash=H1,
        disclosure_plan_hash=H2,
        disclosed_data_classes=("private_test_payload",),
        base_payload_hash=_json_hash(request.private_input),
        tool_catalog_hash=tool_catalog.catalog_hash,
        max_turns=request.limits.max_turns,
        max_tool_calls=request.limits.max_tool_calls,
        max_total_tokens=request.limits.max_total_tokens,
        max_cost_minor_units=request.limits.max_cost_minor_units,
        currency=spec.pricing_currency,
        max_duration_ms=request.limits.max_duration_ms,
        deadline_ms=request.limits.deadline_ms,
        usage_policy_hash=spec.usage_policy_hash,
        pricing_policy_hash=spec.pricing_policy_hash,
        credential_revision_id=None,
    )


def _priced_accounting(execution_id: str) -> UsageAccounting:
    activation, grant = _probe_documents()
    request = _request(activation, grant)
    broker = CapabilityBroker()
    catalog = code_owned_provider_catalog()
    resolved = catalog.resolve(_priced_selection(request, broker))
    return UsageAccounting.create_from_resolved(
        execution_id=execution_id,
        request_fingerprint="c" * 64,
        resolved=resolved,
    )


def _selection_for_catalog_spec(
    request,
    broker: CapabilityBroker,
    catalog: ProviderRuntimeCatalog,
    spec: ProviderRuntimeSpec,
) -> ProviderExecutionSelection:
    base = _priced_selection(request, broker)
    values = {
        field: getattr(base, field)
        for field in ProviderExecutionSelection.__dataclass_fields__
        if field != "content_hash"
    }
    values.update(
        catalog_hash=catalog.catalog_hash,
        spec_hash=spec.content_hash,
        runtime_id=spec.runtime_id,
        runtime_revision=spec.runtime_revision,
        runtime_content_hash=spec.runtime_content_hash,
        usage_policy_hash=spec.usage_policy_hash,
        pricing_policy_hash=spec.pricing_policy_hash,
        currency=spec.pricing_currency,
    )
    return ProviderExecutionSelection.create(**values)


def _authorized_probe_kernel(
    request,
    provider: FakeProvider,
    journal,
    *,
    cancellation: FakeCancellation | None = None,
) -> AgentExecutionKernel:
    broker = CapabilityBroker()
    selection = _priced_selection(request, broker)
    request = replace(
        request,
        provider_approval_id="provider_approval_parent_price",
        provider_selection=selection,
    )
    authority = InMemoryProviderGovernanceAuthority()
    kernel = AgentExecutionKernel(
        provider=provider,
        broker=broker,
        journal=journal,
        clock=FakeClock(),
        cancellation=FakeCancellation() if cancellation is None else cancellation,
        provider_catalog=code_owned_provider_catalog(),
        provider_governance_authority=authority,
    )
    review = kernel.prepare_provider_governance_review(request)
    decision = ProviderGovernanceDecision.create(
        review=review,
        reviewer_id="provider_reviewer_parent_price",
        outcome="approved",
        expires_at_ms=5_000,
    )
    authority.decide(
        decision,
        expected_generation=0,
        expected_review_hash=review.content_hash,
    )
    kernel._test_request = request  # type: ignore[attr-defined]
    kernel._test_provider_authority = authority  # type: ignore[attr-defined]
    kernel._test_provider_decision = decision  # type: ignore[attr-defined]
    return kernel


class ExactParentPricingTests(unittest.TestCase):
    def test_catalog_requires_exact_code_owned_conformance_identity(self) -> None:
        conformance = runtime_spec(_CodeOwnedRuntimeKey.CONFORMANCE)
        mutations = (
            {"runtime_revision": conformance.runtime_revision + 1},
            {"runtime_content_hash": "f" * 64},
            {"usage_policy_hash": "d" * 64},
        )
        for mutation in mutations:
            values = {
                field: getattr(conformance, field)
                for field in ProviderRuntimeSpec.__dataclass_fields__
                if field != "content_hash"
            }
            forged = ProviderRuntimeSpec.create(**(values | mutation))
            with (
                self.subTest(mutation=tuple(mutation)),
                self.assertRaisesRegex(
                    ProviderCatalogError,
                    "provider_pricing_policy_invalid",
                ),
            ):
                ProviderRuntimeCatalog.create((forged,))

    def test_accounting_rejects_durable_forged_conformance_identity(self) -> None:
        conformance = runtime_spec(_CodeOwnedRuntimeKey.CONFORMANCE)
        lineage = {
            "format": "world-forge.private.provider_accounting_lineage",
            "format_version": 1,
            "execution_id": "execution_forged_conformance_accounting",
            "request_fingerprint": "c" * 64,
            "runtime_id": conformance.runtime_id,
            "runtime_revision": conformance.runtime_revision + 1,
            "runtime_content_hash": "f" * 64,
            "runtime_spec_hash": "a" * 64,
            "selection_hash": "b" * 64,
            "usage_policy_hash": "d" * 64,
            "pricing_policy_hash": None,
            "pricing_currency": None,
        }
        lineage["content_hash"] = _json_hash(lineage)

        with self.assertRaisesRegex(
            UsageEvidenceError,
            "provider_usage_policy_invalid",
        ):
            UsageAccounting._from_durable_lineage(lineage)

    def test_event_log_replay_rejects_forged_conformance_identity(self) -> None:
        activation, grant = _documents(capabilities=[], tools=[])
        conformance = runtime_spec(_CodeOwnedRuntimeKey.CONFORMANCE)
        forged_runtime = {
            "id": conformance.runtime_id,
            "revision": conformance.runtime_revision + 1,
            "content_hash": "f" * 64,
        }
        activation["runtime"] = forged_runtime
        activation["content_hash"] = canonical_agent_harness_hash(activation)
        grant["runtime"] = forged_runtime
        grant["activation"] = {
            "id": activation["activation_id"],
            "content_hash": activation["content_hash"],
        }
        grant["content_hash"] = canonical_agent_harness_hash(grant)
        execution_id = activation["execution_id"]
        request_fingerprint = "c" * 64
        lineage = {
            "format": "world-forge.private.provider_accounting_lineage",
            "format_version": 1,
            "execution_id": execution_id,
            "request_fingerprint": request_fingerprint,
            "runtime_id": forged_runtime["id"],
            "runtime_revision": forged_runtime["revision"],
            "runtime_content_hash": forged_runtime["content_hash"],
            "runtime_spec_hash": "a" * 64,
            "selection_hash": "b" * 64,
            "usage_policy_hash": "d" * 64,
            "pricing_policy_hash": None,
            "pricing_currency": None,
        }
        lineage["content_hash"] = _json_hash(lineage)
        commitment = _json_hash(
            {
                "format": "world-forge.private.provider_lineage_request_commitment",
                "format_version": 1,
                "request_fingerprint": request_fingerprint,
                "provider_lineage_hash": lineage["content_hash"],
            }
        )

        with tempfile.TemporaryDirectory() as temporary, AgentEventLog(temporary) as durable:
            self.assertTrue(
                durable.begin_execution(
                    execution_id,
                    "log_forged_conformance",
                    activation,
                    grant,
                    request_fingerprint=request_fingerprint,
                )
            )
            durable.connection.execute(
                """
                INSERT INTO events(execution_id, sequence, event_id, event_hash, event_json)
                VALUES (?, -1, ?, ?, ?)
                """,
                (
                    execution_id,
                    f"lineage_{lineage['content_hash'][:56]}",
                    lineage["content_hash"],
                    json.dumps(lineage, sort_keys=True, separators=(",", ":")).encode(),
                ),
            )
            row = durable.connection.execute(
                "SELECT * FROM executions WHERE execution_id = ?",
                (execution_id,),
            ).fetchone()
            state = durable._row_state_values(row)
            state["request_fingerprint"] = commitment
            durable.connection.execute(
                """
                UPDATE executions SET request_fingerprint = ?, state_hash = ?
                WHERE execution_id = ?
                """,
                (commitment, event_log_module._state_hash(**state), execution_id),
            )
            durable.connection.commit()

            with self.assertRaises(AgentEventLogCorrupt):
                durable.replay_records(execution_id)

    def test_direct_live_probe_lineage_rejects_arbitrary_selected_hashes(self) -> None:
        activation, grant = _probe_documents()
        request = _request(activation, grant)
        broker = CapabilityBroker()
        catalog = code_owned_provider_catalog()
        probe = runtime_spec(_CodeOwnedRuntimeKey.DETERMINISTIC_PROBE)
        resolved = catalog.resolve(_priced_selection(request, broker))
        mutations = (
            {"runtime_spec_hash": "a" * 64},
            {"selection_hash": "b" * 64},
        )
        for mutation in mutations:
            values = {
                "execution_id": activation["execution_id"],
                "request_fingerprint": "c" * 64,
                "runtime_id": probe.runtime_id,
                "runtime_revision": probe.runtime_revision,
                "runtime_content_hash": probe.runtime_content_hash,
                "runtime_spec_hash": resolved.spec.content_hash,
                "selection_hash": resolved.selection.content_hash,
                "usage_policy_hash": probe.usage_policy_hash,
                "pricing_policy_hash": probe.pricing_policy_hash,
                "pricing_currency": probe.pricing_currency,
            }
            with (
                self.subTest(mutation=tuple(mutation)),
                self.assertRaisesRegex(
                    UsageEvidenceError,
                    "provider_usage_policy_invalid",
                ),
            ):
                lineage = ProviderAccountingLineage.create(**(values | mutation))
                UsageAccounting._from_lineage(lineage)

    def test_event_log_begin_rejects_copied_issued_lineage_hash_drift(self) -> None:
        activation, grant = _probe_documents()
        request = _request(activation, grant)
        broker = CapabilityBroker()
        resolved = code_owned_provider_catalog().resolve(_priced_selection(request, broker))
        issued = ProviderAccountingLineage.from_resolved(
            execution_id=activation["execution_id"],
            request_fingerprint="c" * 64,
            resolved=resolved,
        )
        for mutation in ({"runtime_spec_hash": "a" * 64}, {"selection_hash": "b" * 64}):
            document = issued.as_document() | mutation
            document["content_hash"] = _json_hash(
                {key: value for key, value in document.items() if key != "content_hash"}
            )
            hostile = replace(
                issued,
                **mutation,
                content_hash=document["content_hash"],
            )
            with (
                self.subTest(mutation=tuple(mutation)),
                tempfile.TemporaryDirectory() as temporary,
                AgentEventLog(temporary) as durable,
                self.assertRaisesRegex(AgentEventLogError, "event_log_request_invalid"),
            ):
                durable._begin_execution_with_provider_lineage(
                    activation["execution_id"],
                    "log_copied_lineage",
                    activation,
                    grant,
                    request_fingerprint="c" * 64,
                    provider_lineage=hostile,
                )

    def test_priced_accounting_requires_code_owned_catalog_resolution(self) -> None:
        activation, grant = _probe_documents()
        request = _request(activation, grant)
        broker = CapabilityBroker()
        probe = runtime_spec(_CodeOwnedRuntimeKey.DETERMINISTIC_PROBE)
        values = {
            field: getattr(probe, field)
            for field in ProviderRuntimeSpec.__dataclass_fields__
            if field != "content_hash"
        }
        caller_spec = ProviderRuntimeSpec.create(**(values | {"model_id": "caller_probe"}))
        caller_catalog = ProviderRuntimeCatalog.create((caller_spec,))
        resolved = caller_catalog.resolve(
            _selection_for_catalog_spec(request, broker, caller_catalog, caller_spec)
        )

        with self.assertRaisesRegex(
            UsageEvidenceError,
            "provider_usage_policy_invalid",
        ):
            UsageAccounting.create_from_resolved(
                execution_id=activation["execution_id"],
                request_fingerprint="c" * 64,
                resolved=resolved,
            )

    def test_priced_accounting_rejects_copied_resolved_selection(self) -> None:
        activation, grant = _probe_documents()
        request = _request(activation, grant)
        broker = CapabilityBroker()
        resolved = code_owned_provider_catalog().resolve(_priced_selection(request, broker))
        values = {
            field: getattr(resolved.selection, field)
            for field in ProviderExecutionSelection.__dataclass_fields__
            if field != "content_hash"
        }
        changed_selection = ProviderExecutionSelection.create(
            **(values | {"non_secret_config_hash": "e" * 64})
        )
        copied = replace(resolved, selection=changed_selection)

        with self.assertRaisesRegex(
            UsageEvidenceError,
            "provider_usage_policy_invalid",
        ):
            UsageAccounting.create_from_resolved(
                execution_id=activation["execution_id"],
                request_fingerprint="c" * 64,
                resolved=copied,
            )

    def test_kernel_rejects_value_only_copy_of_code_owned_catalog(self) -> None:
        caller_catalog = ProviderRuntimeCatalog.create(code_owned_provider_catalog().specs)
        journal = FakeJournal()
        with self.assertRaisesRegex(KernelError, "provider_catalog_invalid"):
            AgentExecutionKernel(
                provider=FakeProvider([]),
                broker=CapabilityBroker(),
                journal=journal,
                clock=FakeClock(),
                cancellation=FakeCancellation(),
                provider_catalog=caller_catalog,
                provider_governance_authority=InMemoryProviderGovernanceAuthority(),
            )
        self.assertEqual([], journal.operations)

    def test_catalog_authority_rejects_object_new_replace_and_borrowed_owner(self) -> None:
        activation, grant = _probe_documents()
        request = _request(activation, grant)
        broker = CapabilityBroker()
        selection = _priced_selection(request, broker)

        class CatalogSubclass(ProviderRuntimeCatalog):
            pass

        for attack in ("object_new", "replace", "subclass"):
            source = code_owned_provider_catalog()
            if attack == "replace":
                hostile = replace(source)
            else:
                hostile_type = ProviderRuntimeCatalog if attack == "object_new" else CatalogSubclass
                hostile = object.__new__(hostile_type)
                object.__setattr__(
                    hostile,
                    "_entries",
                    object.__getattribute__(source, "_entries"),
                )
                object.__setattr__(hostile, "catalog_hash", source.catalog_hash)
            _borrow_embedded_authority(source, hostile, owner=hostile)

            with (
                self.subTest(attack=attack),
                self.assertRaisesRegex(
                    UsageEvidenceError,
                    "provider_usage_policy_invalid",
                ),
            ):
                UsageAccounting.create_from_resolved(
                    execution_id=f"execution_catalog_{attack}",
                    request_fingerprint="c" * 64,
                    resolved=hostile.resolve(selection),
                )

    def test_generic_catalog_issuer_cannot_authorize_caller_specs(self) -> None:
        activation, grant = _probe_documents()
        request = _request(activation, grant)
        broker = CapabilityBroker()
        probe = runtime_spec(_CodeOwnedRuntimeKey.DETERMINISTIC_PROBE)
        values = {
            field: getattr(probe, field)
            for field in ProviderRuntimeSpec.__dataclass_fields__
            if field != "content_hash"
        }
        caller_spec = ProviderRuntimeSpec.create(**(values | {"model_id": "caller_probe"}))
        caller_catalog = ProviderRuntimeCatalog.create((caller_spec,))
        issuer = getattr(provider_catalog_module, "_issue_code_owned_provider_catalog", None)
        candidate = caller_catalog if issuer is None else issuer(caller_catalog)
        resolved = candidate.resolve(
            _selection_for_catalog_spec(request, broker, candidate, caller_spec)
        )

        with self.assertRaisesRegex(
            UsageEvidenceError,
            "provider_usage_policy_invalid",
        ):
            UsageAccounting.create_from_resolved(
                execution_id="execution_generic_catalog_issuer",
                request_fingerprint="c" * 64,
                resolved=resolved,
            )
        self.assertIsNone(issuer)

    def test_resolved_authority_rejects_copies_subclasses_and_coherent_mutation(self) -> None:
        activation, grant = _probe_documents()
        request = _request(activation, grant)
        broker = CapabilityBroker()

        def fresh():
            return code_owned_provider_catalog().resolve(_priced_selection(request, broker))

        def changed_selection(resolved):
            values = {
                field: getattr(resolved.selection, field)
                for field in ProviderExecutionSelection.__dataclass_fields__
                if field != "content_hash"
            }
            return ProviderExecutionSelection.create(
                **(values | {"non_secret_config_hash": "e" * 64})
            )

        class ResolvedSubclass(ResolvedProviderExecution):
            pass

        for attack in ("object_new", "replace", "subclass", "mutate_registered"):
            source = fresh()
            selection = changed_selection(source)
            if attack == "replace":
                hostile = replace(source, selection=selection)
            elif attack == "mutate_registered":
                hostile = source
                object.__setattr__(hostile, "selection", selection)
                try:
                    authority = object.__getattribute__(hostile, "_authority")
                    object.__setattr__(authority, "selection_hash", selection.content_hash)
                except AttributeError:
                    pass
            else:
                hostile_type = (
                    ResolvedProviderExecution if attack == "object_new" else ResolvedSubclass
                )
                hostile = object.__new__(hostile_type)
                object.__setattr__(hostile, "catalog_hash", source.catalog_hash)
                object.__setattr__(hostile, "spec", source.spec)
                object.__setattr__(hostile, "selection", selection)
            if attack != "mutate_registered":
                _borrow_embedded_authority(
                    source,
                    hostile,
                    owner=hostile,
                    selection_hash=selection.content_hash,
                )

            with (
                self.subTest(attack=attack),
                self.assertRaisesRegex(
                    UsageEvidenceError,
                    "provider_usage_policy_invalid",
                ),
            ):
                UsageAccounting.create_from_resolved(
                    execution_id=f"execution_resolved_{attack}",
                    request_fingerprint="c" * 64,
                    resolved=hostile,
                )

    def test_live_lineage_authority_rejects_proof_theft_and_retargeted_hashes(self) -> None:
        activation, grant = _probe_documents()
        request = _request(activation, grant)
        broker = CapabilityBroker()

        def fresh():
            resolved = code_owned_provider_catalog().resolve(_priced_selection(request, broker))
            return ProviderAccountingLineage.from_resolved(
                execution_id=activation["execution_id"],
                request_fingerprint="c" * 64,
                resolved=resolved,
            )

        class LineageSubclass(ProviderAccountingLineage):
            pass

        for field, value in (("runtime_spec_hash", "a" * 64), ("selection_hash", "b" * 64)):
            for attack in ("object_new", "replace", "subclass", "mutate_registered"):
                source = fresh()
                document = source.as_document() | {field: value}
                content_hash = _json_hash(
                    {key: item for key, item in document.items() if key != "content_hash"}
                )
                if attack == "replace":
                    hostile = replace(source, **{field: value, "content_hash": content_hash})
                elif attack == "mutate_registered":
                    hostile = source
                    object.__setattr__(hostile, field, value)
                    object.__setattr__(hostile, "content_hash", content_hash)
                    try:
                        authority = object.__getattribute__(hostile, "_authority")
                        object.__setattr__(authority, "content_hash", content_hash)
                    except AttributeError:
                        pass
                else:
                    hostile_type = (
                        ProviderAccountingLineage if attack == "object_new" else LineageSubclass
                    )
                    hostile = object.__new__(hostile_type)
                    for name in ProviderAccountingLineage.__dataclass_fields__:
                        if name != "_authority":
                            object.__setattr__(
                                hostile,
                                name,
                                content_hash
                                if name == "content_hash"
                                else value
                                if name == field
                                else getattr(source, name),
                            )
                if attack != "mutate_registered":
                    _borrow_embedded_authority(
                        source,
                        hostile,
                        owner=hostile,
                        content_hash=content_hash,
                    )

                with (
                    self.subTest(field=field, attack=attack),
                    self.assertRaisesRegex(
                        UsageEvidenceError,
                        "provider_usage_policy_invalid",
                    ),
                ):
                    UsageAccounting._from_lineage(hostile)

    def test_authority_registries_release_completed_objects_after_gc(self) -> None:
        activation, grant = _probe_documents()
        request = _request(activation, grant)
        broker = CapabilityBroker()
        selection = _priced_selection(request, broker)
        gc.collect()
        before = (
            len(provider_catalog_module._CODE_OWNED_CATALOG_IDENTITIES),
            len(provider_catalog_module._CODE_OWNED_RESOLUTION_IDENTITIES),
            len(usage_module._LIVE_PROVIDER_LINEAGE_IDENTITIES),
        )

        for index in range(1_000):
            catalog = code_owned_provider_catalog()
            resolved = catalog.resolve(selection)
            lineage = ProviderAccountingLineage.from_resolved(
                execution_id=f"execution_gc_{index}",
                request_fingerprint="c" * 64,
                resolved=resolved,
            )
        del catalog, resolved, lineage
        gc.collect()

        self.assertEqual(
            before,
            (
                len(provider_catalog_module._CODE_OWNED_CATALOG_IDENTITIES),
                len(provider_catalog_module._CODE_OWNED_RESOLUTION_IDENTITIES),
                len(usage_module._LIVE_PROVIDER_LINEAGE_IDENTITIES),
            ),
        )

    def test_authority_registries_keep_live_objects_and_release_collected_objects(
        self,
    ) -> None:
        activation, grant = _probe_documents()
        request = _request(activation, grant)
        broker = CapabilityBroker()
        selection = _priced_selection(request, broker)
        live_catalog = code_owned_provider_catalog()
        live_resolved = live_catalog.resolve(selection)
        live_lineage = ProviderAccountingLineage.from_resolved(
            execution_id="execution_gc_live",
            request_fingerprint="c" * 64,
            resolved=live_resolved,
        )
        gc.collect()

        provider_catalog_module._validate_authoritative_provider_catalog(live_catalog)
        provider_catalog_module._validate_authoritative_resolved(live_resolved)
        self.assertIs(
            live_lineage,
            usage_module.validate_provider_accounting_lineage(live_lineage),
        )

        collected_catalog = code_owned_provider_catalog()
        collected_resolved = collected_catalog.resolve(selection)
        collected_lineage = ProviderAccountingLineage.from_resolved(
            execution_id="execution_gc_collected",
            request_fingerprint="c" * 64,
            resolved=collected_resolved,
        )
        collected_ids = (
            id(collected_catalog),
            id(collected_resolved),
            id(collected_lineage),
        )
        collected_refs = (
            weakref.ref(collected_catalog),
            weakref.ref(collected_resolved),
            weakref.ref(collected_lineage),
        )
        del collected_catalog, collected_resolved, collected_lineage
        gc.collect()

        self.assertEqual((None, None, None), tuple(ref() for ref in collected_refs))
        self.assertNotIn(
            collected_ids[0],
            provider_catalog_module._CODE_OWNED_CATALOG_IDENTITIES,
        )
        self.assertNotIn(
            collected_ids[1],
            provider_catalog_module._CODE_OWNED_RESOLUTION_IDENTITIES,
        )
        self.assertNotIn(
            collected_ids[2],
            usage_module._LIVE_PROVIDER_LINEAGE_IDENTITIES,
        )

    def test_authority_registry_stale_callback_cannot_retire_new_registration(
        self,
    ) -> None:
        activation, grant = _probe_documents()
        request = _request(activation, grant)
        broker = CapabilityBroker()
        selection = _priced_selection(request, broker)
        old_catalog = code_owned_provider_catalog()
        old_resolved = old_catalog.resolve(selection)
        old_lineage = ProviderAccountingLineage.from_resolved(
            execution_id="execution_stale_old",
            request_fingerprint="c" * 64,
            resolved=old_resolved,
        )
        new_catalog = code_owned_provider_catalog()
        new_resolved = new_catalog.resolve(selection)
        new_lineage = ProviderAccountingLineage.from_resolved(
            execution_id="execution_stale_new",
            request_fingerprint="c" * 64,
            resolved=new_resolved,
        )
        cases = (
            (
                provider_catalog_module._CODE_OWNED_CATALOG_IDENTITIES,
                provider_catalog_module._retire_registered_identity,
                old_catalog,
                new_catalog,
            ),
            (
                provider_catalog_module._CODE_OWNED_RESOLUTION_IDENTITIES,
                provider_catalog_module._retire_registered_identity,
                old_resolved,
                new_resolved,
            ),
            (
                usage_module._LIVE_PROVIDER_LINEAGE_IDENTITIES,
                usage_module._retire_registered_identity,
                old_lineage,
                new_lineage,
            ),
        )
        for registry, retire, old_value, new_value in cases:
            with self.subTest(value_type=type(old_value).__name__):
                old_identity = id(old_value)
                old_entry = registry[old_identity]
                newer_entry = registry[id(new_value)]
                registry[old_identity] = newer_entry
                try:
                    retire(registry, old_identity, old_entry[0])
                    self.assertIs(newer_entry, registry[old_identity])
                finally:
                    registry[old_identity] = old_entry

    def test_legacy_journal_signature_remains_compatible_and_pricing_fails_early(
        self,
    ) -> None:
        activation, grant = _documents(capabilities=[], tools=[])
        request = _request(activation, grant)
        legacy = _LegacyExecutionJournal()
        conformance_provider = FakeProvider(
            [ProviderTurnResult("complete", _usage(), completed=True)]
        )
        kernel, _journal = _kernel(conformance_provider, journal=legacy)

        result = kernel.execute(request)
        self.assertEqual("succeeded", result.outcome)
        self.assertEqual("begin", legacy.operations[0])
        self.assertEqual("finalize", legacy.operations[-1])
        self.assertEqual(1, len(conformance_provider.requests))

        priced_activation, priced_grant = _probe_documents()
        priced_request = _request(priced_activation, priced_grant)
        priced_provider = FakeProvider(
            [ProviderTurnResult("complete", _probe_usage(), completed=True)],
            runtime_binding=runtime_identity(_CodeOwnedRuntimeKey.DETERMINISTIC_PROBE),
        )
        priced_legacy = _LegacyExecutionJournal()
        priced_kernel = _authorized_probe_kernel(
            priced_request,
            priced_provider,
            priced_legacy,
        )
        with self.assertRaisesRegex(KernelError, "provider_usage_policy_invalid"):
            priced_kernel.execute(priced_kernel._test_request)  # type: ignore[attr-defined]
        self.assertEqual([], priced_provider.requests)
        self.assertEqual([], priced_legacy.operations)

    def test_execution_journal_public_port_bytes_match_baseline(self) -> None:
        ports = (
            Path(__file__).resolve().parents[1]
            / "src"
            / "worldforge"
            / "agent_harness"
            / "ports.py"
        )
        self.assertEqual(
            "c36fae5d9493ef667614d5a6ac740df5c2fe27a97ec27cd9f210d159fe1d65c6",
            hashlib.sha256(ports.read_bytes()).hexdigest(),
        )

    def test_private_priced_journal_extension_rejects_unpriced_lineage(self) -> None:
        activation, grant = _documents(capabilities=[], tools=[])
        request = _request(activation, grant)
        broker = CapabilityBroker()
        catalog = code_owned_provider_catalog()
        conformance = runtime_spec(_CodeOwnedRuntimeKey.CONFORMANCE)
        resolved = catalog.resolve(
            _selection_for_catalog_spec(request, broker, catalog, conformance)
        )
        lineage = ProviderAccountingLineage.from_resolved(
            execution_id=activation["execution_id"],
            request_fingerprint="c" * 64,
            resolved=resolved,
        )

        with (
            tempfile.TemporaryDirectory() as temporary,
            AgentEventLog(temporary) as durable,
            self.assertRaisesRegex(AgentEventLogError, "event_log_request_invalid"),
        ):
            durable._begin_execution_with_provider_lineage(
                activation["execution_id"],
                "log_unpriced_private_extension",
                activation,
                grant,
                request_fingerprint="c" * 64,
                provider_lineage=lineage,
            )

    def test_catalog_requires_exact_pricing_shape_for_both_code_owned_runtimes(self) -> None:
        policy = code_owned_pricing_policy()
        cases = (
            (
                "probe_pricing_stripped",
                runtime_spec(_CodeOwnedRuntimeKey.DETERMINISTIC_PROBE),
                None,
                None,
            ),
            (
                "probe_pricing_replaced",
                runtime_spec(_CodeOwnedRuntimeKey.DETERMINISTIC_PROBE),
                "d" * 64,
                "USD",
            ),
            (
                "conformance_arbitrary_pricing",
                runtime_spec(_CodeOwnedRuntimeKey.CONFORMANCE),
                "e" * 64,
                "USD",
            ),
            (
                "conformance_probe_pricing",
                runtime_spec(_CodeOwnedRuntimeKey.CONFORMANCE),
                policy.content_hash,
                policy.currency,
            ),
        )
        for name, original, pricing_hash, currency in cases:
            values = {
                field: getattr(original, field)
                for field in ProviderRuntimeSpec.__dataclass_fields__
                if field != "content_hash"
            }
            hostile = ProviderRuntimeSpec.create(
                **(
                    values
                    | {
                        "pricing_policy_hash": pricing_hash,
                        "pricing_currency": currency,
                    }
                )
            )
            with (
                self.subTest(name=name),
                self.assertRaisesRegex(
                    ProviderCatalogError,
                    "provider_pricing_policy_invalid",
                ),
            ):
                ProviderRuntimeCatalog.create((hostile,))

    def test_direct_lineage_requires_closed_two_runtime_pricing_shape(self) -> None:
        probe = runtime_spec(_CodeOwnedRuntimeKey.DETERMINISTIC_PROBE)
        conformance = runtime_spec(_CodeOwnedRuntimeKey.CONFORMANCE)
        for spec, pricing_hash, currency in (
            (probe, None, None),
            (probe, "d" * 64, "USD"),
            (conformance, "e" * 64, "USD"),
        ):
            with (
                self.subTest(
                    runtime_id=spec.runtime_id,
                    pricing_hash=pricing_hash,
                    currency=currency,
                ),
                self.assertRaisesRegex(
                    UsageEvidenceError,
                    "provider_usage_policy_invalid",
                ),
            ):
                ProviderAccountingLineage.create(
                    execution_id="execution_direct_probe_lineage",
                    request_fingerprint="c" * 64,
                    runtime_id=spec.runtime_id,
                    runtime_revision=spec.runtime_revision,
                    runtime_content_hash=spec.runtime_content_hash,
                    runtime_spec_hash=spec.content_hash,
                    selection_hash="b" * 64,
                    usage_policy_hash=spec.usage_policy_hash,
                    pricing_policy_hash=pricing_hash,
                    pricing_currency=currency,
                )
        with self.assertRaisesRegex(
            UsageEvidenceError,
            "provider_usage_policy_invalid",
        ):
            ProviderAccountingLineage.create(
                execution_id="execution_direct_unknown_lineage",
                request_fingerprint="c" * 64,
                runtime_id="caller_runtime",
                runtime_revision=1,
                runtime_content_hash="a" * 64,
                runtime_spec_hash="b" * 64,
                selection_hash="c" * 64,
                usage_policy_hash="d" * 64,
                pricing_policy_hash="e" * 64,
                pricing_currency="USD",
            )

    def test_kernel_input_cannot_carry_a_stripped_probe_catalog(self) -> None:
        probe = runtime_spec(_CodeOwnedRuntimeKey.DETERMINISTIC_PROBE)
        values = {
            field: getattr(probe, field)
            for field in ProviderRuntimeSpec.__dataclass_fields__
            if field != "content_hash"
        }
        stripped = ProviderRuntimeSpec.create(
            **(
                values
                | {
                    "pricing_policy_hash": None,
                    "pricing_currency": None,
                }
            )
        )
        journal = FakeJournal()

        with self.assertRaisesRegex(
            ProviderCatalogError,
            "provider_pricing_policy_invalid",
        ):
            caller_catalog = ProviderRuntimeCatalog.create(
                (runtime_spec(_CodeOwnedRuntimeKey.CONFORMANCE), stripped)
            )
            AgentExecutionKernel(
                provider=FakeProvider(
                    [],
                    runtime_binding=runtime_identity(_CodeOwnedRuntimeKey.DETERMINISTIC_PROBE),
                ),
                broker=CapabilityBroker(),
                journal=journal,
                clock=FakeClock(),
                cancellation=FakeCancellation(),
                provider_catalog=caller_catalog,
                provider_governance_authority=InMemoryProviderGovernanceAuthority(),
            )
        self.assertEqual([], journal.operations)

    def test_catalog_rejects_canonical_xts_policy_rebound_to_conformance_runtime(self) -> None:
        policy = code_owned_pricing_policy()
        conformance = runtime_spec(_CodeOwnedRuntimeKey.CONFORMANCE)
        values = {
            field: getattr(conformance, field)
            for field in ProviderRuntimeSpec.__dataclass_fields__
            if field != "content_hash"
        }
        rebound = ProviderRuntimeSpec.create(
            **(
                values
                | {
                    "usage_policy_hash": policy.usage_policy_hash,
                    "pricing_policy_hash": policy.content_hash,
                    "pricing_currency": policy.currency,
                }
            )
        )

        with self.assertRaisesRegex(ProviderCatalogError, "provider_pricing_policy_invalid"):
            ProviderRuntimeCatalog.create((rebound,))

    def test_priced_accounting_rejects_opaque_runtime_and_selection_hashes(self) -> None:
        policy = code_owned_pricing_policy()

        with self.assertRaisesRegex(UsageEvidenceError, "provider_usage_policy_invalid"):
            UsageAccounting.create(
                execution_id="execution_opaque_priced_lineage",
                runtime_spec_hash="a" * 64,
                selection_hash="b" * 64,
                usage_policy_hash=policy.usage_policy_hash,
                pricing_policy_hash=policy.content_hash,
            )

        activation, grant = _probe_documents()
        request = _request(activation, grant)
        broker = CapabilityBroker()
        catalog = code_owned_provider_catalog()
        spec = runtime_spec(_CodeOwnedRuntimeKey.DETERMINISTIC_PROBE)
        selection = _priced_selection(request, broker)
        caller_forged_resolution = ResolvedProviderExecution(
            catalog.catalog_hash,
            spec,
            selection,
        )
        with self.assertRaisesRegex(UsageEvidenceError, "provider_usage_policy_invalid"):
            UsageAccounting.create_from_resolved(
                execution_id="execution_caller_forged_resolution",
                request_fingerprint="c" * 64,
                resolved=caller_forged_resolution,
            )

    def test_closed_probe_policy_binds_exact_runtime_usage_and_synthetic_rates(self) -> None:
        policy = code_owned_pricing_policy()
        probe = runtime_identity(_CodeOwnedRuntimeKey.DETERMINISTIC_PROBE)

        self.assertEqual(
            {
                "runtime_id": probe["id"],
                "runtime_revision": probe["revision"],
                "runtime_content_hash": probe["content_hash"],
                "usage_policy_hash": code_owned_usage_policy_hash(probe["id"]),
                "policy_id": "deterministic_probe_synthetic_xts",
                "policy_version": 1,
                "currency": "XTS",
                "denominator": 4,
                "uncached_input_numerator": 2,
                "cached_input_numerator": 2,
                "output_numerator": 3,
                "rounding_mode": "ceiling_at_execution_total_v1",
            },
            {
                key: value
                for key, value in policy.as_document().items()
                if key not in {"format", "format_version", "content_hash"}
            },
        )
        self.assertEqual(canonical_pricing_hash(policy.as_document()), policy.content_hash)
        self.assertEqual(
            policy,
            resolve_code_owned_pricing_policy(
                policy.content_hash,
                policy.usage_policy_hash,
            ),
        )

        catalog = code_owned_provider_catalog()
        specs = {spec.runtime_id: spec for spec in catalog.specs}
        self.assertEqual(2, len(specs))
        self.assertIsNone(specs["worldforge_conformance_provider"].pricing_policy_hash)
        self.assertEqual(
            (policy.content_hash, "XTS"),
            (
                specs["worldforge_deterministic_probe_provider"].pricing_policy_hash,
                specs["worldforge_deterministic_probe_provider"].pricing_currency,
            ),
        )

    def test_exact_scalars_intermediate_overflow_and_policy_drift_fail_closed(self) -> None:
        class IntAlias(int):
            pass

        policy = code_owned_pricing_policy()
        for field, value in (
            ("denominator", 0),
            ("denominator", True),
            ("uncached_input_numerator", -1),
            ("output_numerator", 1.0),
            ("cached_input_numerator", Decimal("1")),
            ("runtime_revision", "1"),
            ("policy_version", IntAlias(1)),
        ):
            values = {
                name: getattr(policy, name)
                for name in ExactPricingPolicy.__dataclass_fields__
                if name != "content_hash"
            }
            values[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(PricingAuthorityError):
                ExactPricingPolicy.create(**values)

        for input_tokens in (True, IntAlias(1), MAX_SAFE_INTEGER):
            with self.subTest(input_tokens=input_tokens), self.assertRaises(PricingAuthorityError):
                calculate_execution_cost(
                    policy,
                    input_tokens=input_tokens,
                    output_tokens=1,
                    cached_input_tokens=None,
                )

        forged = dataclasses.replace(policy)
        object.__setattr__(forged, "content_hash", "0" * 64)
        with self.assertRaises(PricingAuthorityError):
            calculate_execution_cost(
                forged,
                input_tokens=1,
                output_tokens=1,
                cached_input_tokens=None,
            )
        with self.assertRaises(PricingAuthorityError):
            resolve_code_owned_pricing_policy("0" * 64, policy.usage_policy_hash)

        detached = code_owned_pricing_policy()
        object.__setattr__(detached, "output_numerator", 4)
        self.assertEqual(policy, code_owned_pricing_policy())

        accounting = _priced_accounting("execution_mutated_price_policy")
        policy_values = {
            field: getattr(policy, field)
            for field in ExactPricingPolicy.__dataclass_fields__
            if field != "content_hash"
        }
        accounting._pricing_policy = ExactPricingPolicy.create(  # type: ignore[attr-defined]
            **(policy_values | {"output_numerator": 4})
        )
        with self.assertRaises(UsageEvidenceError):
            accounting.add_provider_turn(
                input_tokens=_probe_token(1),
                output_tokens=_probe_token(2),
                cached_input_tokens=_unavailable_cache(),
                worker_cost=_unavailable_cost(),
            )
        self.assertEqual(0, accounting.turn_count)

        activation, grant = _probe_documents()
        request = _request(
            activation,
            grant,
            max_total_tokens=MAX_SAFE_INTEGER,
        )
        overflow_usage = ProviderUsage(
            _probe_token(MAX_SAFE_INTEGER),
            _probe_token(0),
            _unavailable_cache(),
            _unavailable_cost(),
        )
        provider = FakeProvider(
            [ProviderTurnResult("overflow", overflow_usage, completed=True)],
            runtime_binding=runtime_identity(_CodeOwnedRuntimeKey.DETERMINISTIC_PROBE),
        )
        kernel = _authorized_probe_kernel(request, provider, FakeJournal())
        result = kernel.execute(kernel._test_request)  # type: ignore[attr-defined]
        self.assertEqual(["provider_usage_invalid"], result.receipt["failure_codes"])
        self.assertEqual(
            (0, 0, None),
            (
                result.receipt["usage"]["input_tokens"],
                result.receipt["usage"]["output_tokens"],
                result.receipt["usage"]["cost_minor_units"],
            ),
        )

    def test_cache_unavailable_is_priceable_only_for_equal_rates(self) -> None:
        policy = code_owned_pricing_policy()
        self.assertEqual(
            2,
            calculate_execution_cost(
                policy,
                input_tokens=1,
                output_tokens=1,
                cached_input_tokens=None,
            ),
        )
        unequal = ExactPricingPolicy.create(
            runtime_id="unregistered_pricing_probe",
            runtime_revision=1,
            runtime_content_hash="3" * 64,
            usage_policy_hash="4" * 64,
            policy_id="unregistered_unequal_cache_rate",
            policy_version=1,
            currency="XTS",
            denominator=4,
            uncached_input_numerator=2,
            cached_input_numerator=1,
            output_numerator=3,
            rounding_mode="ceiling_at_execution_total_v1",
        )
        self.assertIsNone(
            calculate_execution_cost(
                unequal,
                input_tokens=1,
                output_tokens=1,
                cached_input_tokens=None,
            )
        )
        with self.assertRaises(PricingAuthorityError):
            resolve_code_owned_pricing_policy(
                unequal.content_hash,
                unequal.usage_policy_hash,
            )

    def test_execution_total_rounding_is_split_invariant_and_recomputed(self) -> None:
        policy = code_owned_pricing_policy()

        def accounting(execution_id: str) -> UsageAccounting:
            return _priced_accounting(execution_id)

        split = accounting("execution_price_split")
        for _ in range(2):
            split.add_provider_turn(
                input_tokens=_probe_token(1),
                output_tokens=_probe_token(1),
                cached_input_tokens=_unavailable_cache(),
                worker_cost=_unavailable_cost(),
            )
        combined = accounting("execution_price_combined")
        combined.add_provider_turn(
            input_tokens=_probe_token(2),
            output_tokens=_probe_token(2),
            cached_input_tokens=_unavailable_cache(),
            worker_cost=_unavailable_cost(),
        )
        self.assertEqual(3, split.recognized_totals["cost_minor_units"])
        self.assertEqual(split.recognized_totals, combined.recognized_totals)
        split_turns = split.seal(receipt_hash="7" * 64)["turns"]
        self.assertEqual([2, 1], [turn["cost"]["value"] for turn in split_turns])

        document = split.seal(receipt_hash="7" * 64)
        hostile = json.loads(json.dumps(document))
        hostile["turns"][0]["cost"]["value"] = 3
        hostile["recognized_totals"]["cost_minor_units"] = 4
        hostile["content_hash"] = canonical_usage_hash(hostile)
        with self.assertRaises(PricingAuthorityError):
            resolve_code_owned_pricing_policy(
                policy.content_hash,
                "8" * 64,
            )
        trusted_lineage = split.provider_lineage
        self.assertIsNotNone(trusted_lineage)
        with (
            mock.patch.object(
                pricing_module,
                "_verify_recorded_execution_cost",
                wraps=pricing_module._verify_recorded_execution_cost,
            ) as verify_recorded_cost,
            self.assertRaisesRegex(UsageEvidenceError, "provider_usage_invalid"),
        ):
            validate_usage_accounting(
                hostile,
                trusted_lineage=trusted_lineage.as_document(),  # type: ignore[union-attr]
            )
        self.assertEqual(1, verify_recorded_cost.call_count)

    def test_worker_money_is_rejected_after_parent_accounting_and_never_ledgered(self) -> None:
        activation, grant = _probe_documents()
        forged_costs = (
            CostEvidence.create(
                state="observed",
                source_kind="provider_result",
                value=0,
                currency="XTS",
            ),
            CostEvidence.create(
                state="derived",
                source_kind="parent_pricing_policy",
                value=0,
                currency="XTS",
                policy_hash=code_owned_pricing_policy().content_hash,
            ),
        )
        for forged_money in forged_costs:
            with self.subTest(state=forged_money.state):
                provider = FakeProvider(
                    [
                        ProviderTurnResult(
                            "forged",
                            _probe_usage(cost=forged_money),
                            completed=True,
                        )
                    ],
                    runtime_binding=runtime_identity(_CodeOwnedRuntimeKey.DETERMINISTIC_PROBE),
                )
                request = _request(activation, grant)
                journal = FakeJournal()
                kernel = _authorized_probe_kernel(request, provider, journal)
                result = kernel.execute(kernel._test_request)  # type: ignore[attr-defined]

                self.assertEqual(["provider_usage_invalid"], result.receipt["failure_codes"])
                self.assertEqual(
                    {"cost_minor_units": 2, "currency": "XTS"},
                    {
                        "cost_minor_units": result.receipt["usage"]["cost_minor_units"],
                        "currency": result.receipt["usage"]["currency"],
                    },
                )
                self.assertEqual(
                    "parent_pricing_policy",
                    journal.usage_accounting["turns"][0]["cost"]["source_kind"],
                )
                self.assertNotEqual(
                    forged_money.as_document(),
                    journal.usage_accounting["turns"][0]["cost"],
                )

    def test_optional_cost_ceiling_and_budget_precedence_use_exact_xts(self) -> None:
        activation, grant = _probe_documents()
        cases = (
            (2, 2, "succeeded", []),
            (2, 1, "failed", ["cost_budget_exceeded"]),
            (1, 1, "failed", ["token_budget_exceeded"]),
        )
        for max_tokens, max_cost, outcome, failures in cases:
            with self.subTest(max_tokens=max_tokens, max_cost=max_cost):
                request = _request(
                    activation,
                    grant,
                    max_total_tokens=max_tokens,
                    max_cost_minor_units=max_cost,
                    currency="XTS",
                )
                provider = FakeProvider(
                    [ProviderTurnResult("priced", _probe_usage(), completed=True)],
                    runtime_binding=runtime_identity(_CodeOwnedRuntimeKey.DETERMINISTIC_PROBE),
                )
                journal = FakeJournal()
                kernel = _authorized_probe_kernel(request, provider, journal)
                result = kernel.execute(kernel._test_request)  # type: ignore[attr-defined]
                self.assertEqual(outcome, result.outcome)
                self.assertEqual(failures, result.receipt["failure_codes"])
                self.assertEqual(2, result.receipt["usage"]["cost_minor_units"])

        no_ceiling = _request(activation, grant)
        broker = CapabilityBroker()
        selection = _priced_selection(no_ceiling, broker)
        self.assertIsNone(selection.max_cost_minor_units)
        self.assertEqual("XTS", selection.currency)
        values = {
            field: getattr(selection, field)
            for field in ProviderExecutionSelection.__dataclass_fields__
            if field != "content_hash"
        }
        for field, value in (
            ("currency", "USD"),
            ("pricing_policy_hash", "0" * 64),
            ("usage_policy_hash", "8" * 64),
            ("runtime_content_hash", "9" * 64),
        ):
            with self.subTest(drift=field):
                drifted = ProviderExecutionSelection.create(**(values | {field: value}))
                with self.assertRaises(ProviderCatalogError):
                    code_owned_provider_catalog().resolve(drifted)

    def test_pricing_starts_only_after_durable_begin_and_duplicate_does_zero_work(self) -> None:
        activation, grant = _probe_documents()
        request = _request(activation, grant)
        provider = FakeProvider(
            [ProviderTurnResult("priced", _probe_usage(), completed=True)],
            runtime_binding=runtime_identity(_CodeOwnedRuntimeKey.DETERMINISTIC_PROBE),
        )
        journal = FakeJournal()
        kernel = _authorized_probe_kernel(request, provider, journal)
        resolved_calls: list[tuple[str, ...]] = []
        original = resolve_code_owned_pricing_policy

        def observed_resolve(*args):
            resolved_calls.append(tuple(journal.operations))
            return original(*args)

        with mock.patch(
            "worldforge.agent_harness.pricing.resolve_code_owned_pricing_policy",
            side_effect=observed_resolve,
        ):
            result = kernel.execute(kernel._test_request)  # type: ignore[attr-defined]
        self.assertEqual("succeeded", result.outcome)
        self.assertEqual(
            (2, "XTS"),
            (
                result.receipt["usage"]["cost_minor_units"],
                result.receipt["usage"]["currency"],
            ),
        )
        self.assertTrue(resolved_calls)
        self.assertTrue(all("begin" in operations for operations in resolved_calls))

        provider = FakeProvider(
            [ProviderTurnResult("priced", _probe_usage(), completed=True)],
            runtime_binding=runtime_identity(_CodeOwnedRuntimeKey.DETERMINISTIC_PROBE),
        )
        with tempfile.TemporaryDirectory() as temporary, AgentEventLog(temporary) as durable:
            kernel = _authorized_probe_kernel(request, provider, durable)
            coordinator = AgentExecutionCoordinator(kernel=kernel, event_log=durable)
            with (
                mock.patch.object(
                    UsageAccounting,
                    "add_provider_turn",
                    autospec=True,
                    wraps=UsageAccounting.add_provider_turn,
                ) as live_pricer,
                mock.patch(
                    "worldforge.agent_harness.pricing.calculate_execution_cost",
                    wraps=calculate_execution_cost,
                ) as live_calculator,
            ):
                first = coordinator.execute(kernel._test_request)  # type: ignore[attr-defined]
                duplicate = coordinator.execute(kernel._test_request)  # type: ignore[attr-defined]
        self.assertEqual("executed", first.disposition)
        self.assertEqual("existing_terminal", duplicate.disposition)
        self.assertEqual(first.records, duplicate.records)
        self.assertEqual(1, live_pricer.call_count)
        self.assertEqual(1, live_calculator.call_count)
        self.assertEqual(1, len(provider.requests))

    def test_cost_is_accounted_before_cancellation_revocation_and_nested_failure(self) -> None:
        activation, grant = _probe_documents()
        request = _request(
            activation,
            grant,
            max_cost_minor_units=1,
            currency="XTS",
        )

        cancellation = FakeCancellation()

        def cancel_after_usage(_request):
            cancellation.cancelled = True
            return ProviderTurnResult("cancelled", _probe_usage(), completed=True)

        cancelled_provider = FakeProvider(
            [cancel_after_usage],
            runtime_binding=runtime_identity(_CodeOwnedRuntimeKey.DETERMINISTIC_PROBE),
        )
        cancelled_kernel = _authorized_probe_kernel(
            request,
            cancelled_provider,
            FakeJournal(),
            cancellation=cancellation,
        )
        cancelled = cancelled_kernel.execute(cancelled_kernel._test_request)  # type: ignore[attr-defined]
        self.assertEqual("failed", cancelled.outcome)
        self.assertEqual(["cost_budget_exceeded"], cancelled.receipt["failure_codes"])
        self.assertEqual(2, cancelled.receipt["usage"]["cost_minor_units"])

        revocation_box: dict[str, object] = {}

        def revoke_after_usage(_request):
            authority = revocation_box["authority"]
            decision = revocation_box["decision"]
            authority.revoke(  # type: ignore[attr-defined]
                decision.approval_id,  # type: ignore[attr-defined]
                expected_generation=1,
                expected_decision_hash=decision.content_hash,  # type: ignore[attr-defined]
            )
            return ProviderTurnResult("revoked", _probe_usage(), completed=True)

        revoked_provider = FakeProvider(
            [revoke_after_usage],
            runtime_binding=runtime_identity(_CodeOwnedRuntimeKey.DETERMINISTIC_PROBE),
        )
        revoked_kernel = _authorized_probe_kernel(request, revoked_provider, FakeJournal())
        revocation_box.update(
            authority=revoked_kernel._test_provider_authority,  # type: ignore[attr-defined]
            decision=revoked_kernel._test_provider_decision,  # type: ignore[attr-defined]
        )
        revoked = revoked_kernel.execute(revoked_kernel._test_request)  # type: ignore[attr-defined]
        self.assertEqual("failed", revoked.outcome)
        self.assertEqual(["cost_budget_exceeded"], revoked.receipt["failure_codes"])
        self.assertEqual(2, revoked.receipt["usage"]["cost_minor_units"])

        nested_provider = FakeProvider(
            [
                ProviderTurnResult(
                    None,
                    _probe_usage(),
                    completed=True,
                    nested_failure_code="worker_protocol_result_invalid",
                )
            ],
            runtime_binding=runtime_identity(_CodeOwnedRuntimeKey.DETERMINISTIC_PROBE),
        )
        nested_kernel = _authorized_probe_kernel(request, nested_provider, FakeJournal())
        nested = nested_kernel.execute(nested_kernel._test_request)  # type: ignore[attr-defined]
        self.assertEqual("failed", nested.outcome)
        self.assertEqual(["cost_budget_exceeded"], nested.receipt["failure_codes"])
        self.assertEqual(2, nested.receipt["usage"]["cost_minor_units"])

    def test_event_log_rejects_rehashed_priced_accounting_tamper(self) -> None:
        activation, grant = _probe_documents()
        request = _request(activation, grant)
        provider = FakeProvider(
            [ProviderTurnResult("priced", _probe_usage(), completed=True)],
            runtime_binding=runtime_identity(_CodeOwnedRuntimeKey.DETERMINISTIC_PROBE),
        )
        with tempfile.TemporaryDirectory() as temporary, AgentEventLog(temporary) as durable:
            kernel = _authorized_probe_kernel(request, provider, durable)
            result = kernel.execute(kernel._test_request)  # type: ignore[attr-defined]
            accounting = json.loads(
                durable.replay_records(result.receipt["execution_id"]).usage_accounting_bytes
            )
            accounting["turns"][0]["cost"]["value"] = 3
            accounting["recognized_totals"]["cost_minor_units"] = 3
            accounting["content_hash"] = canonical_usage_hash(accounting)
            durable.connection.execute(
                "UPDATE usage_accounting SET accounting_hash = ?, accounting_json = ?",
                (
                    accounting["content_hash"],
                    json.dumps(
                        accounting,
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode("utf-8"),
                ),
            )
            durable.connection.commit()
            with self.assertRaises(AgentEventLogCorrupt):
                durable.replay_records(result.receipt["execution_id"])

    def test_event_log_rejects_individual_and_joint_rehashed_priced_lineage(self) -> None:
        activation, grant = _probe_documents()
        mutations = (
            {"runtime_spec_hash": "a" * 64},
            {"selection_hash": "b" * 64},
            {"runtime_spec_hash": "a" * 64, "selection_hash": "b" * 64},
        )
        for mutation in mutations:
            with self.subTest(mutation=tuple(mutation)), tempfile.TemporaryDirectory() as temporary:
                request = _request(activation, grant)
                provider = FakeProvider(
                    [ProviderTurnResult("priced", _probe_usage(), completed=True)],
                    runtime_binding=runtime_identity(_CodeOwnedRuntimeKey.DETERMINISTIC_PROBE),
                )
                with AgentEventLog(temporary) as durable:
                    kernel = _authorized_probe_kernel(request, provider, durable)
                    result = kernel.execute(kernel._test_request)  # type: ignore[attr-defined]
                    accounting = json.loads(
                        durable.replay_records(
                            result.receipt["execution_id"]
                        ).usage_accounting_bytes
                    )
                    accounting.update(mutation)
                    accounting["content_hash"] = canonical_usage_hash(accounting)
                    durable.connection.execute(
                        "UPDATE usage_accounting SET accounting_hash = ?, accounting_json = ?",
                        (
                            accounting["content_hash"],
                            json.dumps(
                                accounting,
                                sort_keys=True,
                                separators=(",", ":"),
                            ).encode("utf-8"),
                        ),
                    )
                    durable.connection.commit()
                    with self.assertRaises(AgentEventLogCorrupt):
                        durable.replay_records(result.receipt["execution_id"])

    def test_event_log_finalize_rejects_individual_and_joint_priced_lineage_drift(self) -> None:
        activation, grant = _probe_documents()
        mutations = (
            {"runtime_spec_hash": "a" * 64},
            {"selection_hash": "b" * 64},
            {"runtime_spec_hash": "a" * 64, "selection_hash": "b" * 64},
        )
        for mutation in mutations:
            with self.subTest(mutation=tuple(mutation)), tempfile.TemporaryDirectory() as temporary:
                request = _request(activation, grant)
                provider = FakeProvider(
                    [ProviderTurnResult("priced", _probe_usage(), completed=True)],
                    runtime_binding=runtime_identity(_CodeOwnedRuntimeKey.DETERMINISTIC_PROBE),
                )
                with AgentEventLog(temporary) as durable:
                    kernel = _authorized_probe_kernel(request, provider, durable)
                    original_finalize = durable.finalize
                    rejected: list[str] = []

                    def mutate_before_finalize(
                        execution_id,
                        receipt,
                        event,
                        usage_accounting,
                        _mutation=mutation,
                        _finalize=original_finalize,
                        _rejected=rejected,
                        **expected,
                    ):
                        hostile = json.loads(json.dumps(usage_accounting))
                        hostile.update(_mutation)
                        hostile["content_hash"] = canonical_usage_hash(hostile)
                        try:
                            return _finalize(
                                execution_id,
                                receipt,
                                event,
                                hostile,
                                **expected,
                            )
                        except AgentEventLogCorrupt as exc:
                            _rejected.append(exc.reason_code)
                            raise

                    with (
                        mock.patch.object(
                            durable,
                            "finalize",
                            side_effect=mutate_before_finalize,
                        ),
                        self.assertRaisesRegex(KernelError, "journal_finalization_ambiguous"),
                    ):
                        kernel.execute(kernel._test_request)  # type: ignore[attr-defined]
                    self.assertEqual(["event_log_usage_accounting_corrupt"], rejected)
                    self.assertEqual(
                        "open",
                        durable.replay_records(activation["execution_id"]).state,
                    )

    def test_event_log_semantic_linkage_rejects_partial_joint_lineage_rehash(self) -> None:
        activation, grant = _probe_documents()
        request = _request(activation, grant)
        provider = FakeProvider(
            [ProviderTurnResult("priced", _probe_usage(), completed=True)],
            runtime_binding=runtime_identity(_CodeOwnedRuntimeKey.DETERMINISTIC_PROBE),
        )
        with tempfile.TemporaryDirectory() as temporary, AgentEventLog(temporary) as durable:
            kernel = _authorized_probe_kernel(request, provider, durable)
            result = kernel.execute(kernel._test_request)  # type: ignore[attr-defined]
            execution_id = result.receipt["execution_id"]
            lineage_row = durable.connection.execute(
                "SELECT event_json FROM events WHERE execution_id = ? AND sequence = -1",
                (execution_id,),
            ).fetchone()
            lineage = json.loads(lineage_row["event_json"])
            records = durable.replay_records(execution_id)
            stored_fingerprint = durable.connection.execute(
                "SELECT request_fingerprint FROM executions WHERE execution_id = ?",
                (execution_id,),
            ).fetchone()["request_fingerprint"]
            self.assertEqual(records.request_fingerprint, lineage["request_fingerprint"])
            self.assertNotEqual(records.request_fingerprint, stored_fingerprint)
            accounting = json.loads(records.usage_accounting_bytes)
            # Keep the execution row unchanged: this is partial relational drift,
            # not a same-UID whole-store authenticity claim (ADR-0032).
            for document in (lineage, accounting):
                document["runtime_spec_hash"] = "a" * 64
                document["selection_hash"] = "b" * 64
                document["content_hash"] = _json_hash(
                    {key: value for key, value in document.items() if key != "content_hash"}
                )
            durable.connection.execute(
                """
                UPDATE events SET event_id = ?, event_hash = ?, event_json = ?
                WHERE execution_id = ? AND sequence = -1
                """,
                (
                    f"lineage_{lineage['content_hash'][:56]}",
                    lineage["content_hash"],
                    json.dumps(lineage, sort_keys=True, separators=(",", ":")).encode("utf-8"),
                    execution_id,
                ),
            )
            durable.connection.execute(
                "UPDATE usage_accounting SET accounting_hash = ?, accounting_json = ?",
                (
                    accounting["content_hash"],
                    json.dumps(accounting, sort_keys=True, separators=(",", ":")).encode("utf-8"),
                ),
            )
            durable.connection.commit()

            with self.assertRaises(AgentEventLogCorrupt):
                durable.replay_records(execution_id)

    def test_legacy_accounting_is_never_repriced_and_worker_identities_stay_pinned(self) -> None:
        legacy = build_legacy_usage_accounting(
            {
                "execution_id": "execution_legacy_price",
                "content_hash": "9" * 64,
                "usage": {
                    "input_tokens": 1,
                    "output_tokens": 1,
                    "cached_input_tokens": 0,
                    "duration_ms": 1,
                    "cost_minor_units": 99,
                    "currency": "USD",
                },
            }
        )
        with mock.patch(
            "worldforge.agent_harness.pricing.resolve_code_owned_pricing_policy",
            side_effect=AssertionError("legacy rows must not be repriced"),
        ):
            self.assertEqual(legacy, validate_usage_accounting(legacy))

        self.assertEqual(
            {
                "worldforge_conformance_provider": (
                    4,
                    "baf4d89794aba6003a5d7544d34933aee929517f1b7b47fbe06c2784c7f650b8",
                ),
                "worldforge_deterministic_probe_provider": (
                    6,
                    "8ac9baf3afe72b0a9c27277c33193ef7ffd1253aea9b0abbb996e65cb8c75635",
                ),
            },
            {
                identity["id"]: (identity["revision"], identity["content_hash"])
                for identity in (runtime_identity(key) for key in _CodeOwnedRuntimeKey)
            },
        )
        self.assertEqual(3, worker_protocol_module._PROTOCOL_VERSION)


if __name__ == "__main__":
    unittest.main()
