from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import sys
import tempfile
import threading
import time
import unittest
from dataclasses import replace

from tests.agent_harness_fakes import (
    FakeCancellation,
    FakeClock,
    FakeJournal,
    FakeProvider,
)
from tests.test_agent_execution_kernel import _documents, _request, _usage
from worldforge.agent_harness import (
    AgentEventLog,
    AgentExecutionCoordinator,
    AgentExecutionKernel,
    CapabilityBroker,
    KernelError,
)
from worldforge.agent_harness.ports import ProviderTurnResult
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
    ProviderGovernanceError,
    ProviderGovernanceReview,
)
from worldforge.agent_harness.supervisor import OneShotProviderSupervisor
from worldforge.agent_harness.worker_registry import (
    _CodeOwnedRuntimeKey,
    fixed_provider_catalog,
    fixed_runtime_spec,
    runtime_spec,
)

H0 = "0" * 64
H1 = "1" * 64
H2 = "2" * 64
H3 = "3" * 64
H4 = "4" * 64
H5 = "5" * 64
H6 = "6" * 64
H7 = "7" * 64
H8 = "8" * 64
H9 = "9" * 64


def _spec(**changes: object) -> ProviderRuntimeSpec:
    values: dict[str, object] = {
        "runtime_id": "worldforge_conformance_provider",
        "runtime_revision": 2,
        "runtime_content_hash": H1,
        "provider_id": "worldforge",
        "model_id": "conformance",
        "model_version": "2",
        "deployment_class": "local",
        "network_scope": "none",
        "endpoint_origin": None,
        "endpoint_policy_hash": None,
        "egress_enforcement_hash": None,
        "telemetry_attestation_hash": None,
        "pricing_policy_hash": None,
        "pricing_currency": None,
        "credential_requirement_hash": None,
        "redirects_disabled": True,
        "supported_platforms": ("linux",),
        "production_eligible": False,
    }
    values.update(changes)
    return ProviderRuntimeSpec.create(**values)


def _catalog(spec: ProviderRuntimeSpec | None = None) -> ProviderRuntimeCatalog:
    return ProviderRuntimeCatalog.create((_spec() if spec is None else spec,))


def _selection(
    *,
    catalog: ProviderRuntimeCatalog | None = None,
    spec: ProviderRuntimeSpec | None = None,
    **changes: object,
) -> ProviderExecutionSelection:
    spec = _spec() if spec is None else spec
    catalog = _catalog(spec) if catalog is None else catalog
    values: dict[str, object] = {
        "catalog_hash": catalog.catalog_hash,
        "spec_hash": spec.content_hash,
        "runtime_id": spec.runtime_id,
        "runtime_revision": spec.runtime_revision,
        "runtime_content_hash": spec.runtime_content_hash,
        "non_secret_config_hash": H2,
        "disclosure_plan_hash": H3,
        "disclosed_data_classes": ("private_test_payload",),
        "base_payload_hash": H4,
        "tool_catalog_hash": H5,
        "max_turns": 4,
        "max_tool_calls": 2,
        "max_total_tokens": 100,
        "max_cost_minor_units": 10,
        "currency": "USD",
        "max_duration_ms": 1_000,
        "deadline_ms": 2_000,
        "pricing_policy_hash": None,
        "credential_revision_id": None,
    }
    values.update(changes)
    return ProviderExecutionSelection.create(**values)


def _review(**changes: object) -> ProviderGovernanceReview:
    resolved = _catalog().resolve(_selection())
    values: dict[str, object] = {
        "approval_id": "provider_approval_01",
        "execution_id": "execution_minimal_01",
        "activation_hash": H6,
        "grant_hash": H7,
        "work_order_hash": H8,
        "private_input_hash": H4,
        "resolved": resolved,
    }
    values.update(changes)
    return ProviderGovernanceReview.create(**values)


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


def _execution_selection(
    request,
    broker: CapabilityBroker,
    *,
    catalog: ProviderRuntimeCatalog | None = None,
    spec: ProviderRuntimeSpec | None = None,
    **changes: object,
) -> ProviderExecutionSelection:
    catalog = fixed_provider_catalog() if catalog is None else catalog
    spec = fixed_runtime_spec() if spec is None else spec
    tool_catalog = broker.eligible_tool_catalog(
        effective_capabilities=frozenset(request.grant["effective_capability_ids"]),
        effective_tools=frozenset(request.grant["effective_tool_ids"]),
    )
    limits = request.limits
    values: dict[str, object] = {
        "catalog_hash": catalog.catalog_hash,
        "spec_hash": spec.content_hash,
        "runtime_id": spec.runtime_id,
        "runtime_revision": spec.runtime_revision,
        "runtime_content_hash": spec.runtime_content_hash,
        "non_secret_config_hash": H2,
        "disclosure_plan_hash": H3,
        "disclosed_data_classes": ("private_test_payload",),
        "base_payload_hash": _json_hash(request.private_input),
        "tool_catalog_hash": tool_catalog.catalog_hash,
        "max_turns": limits.max_turns,
        "max_tool_calls": limits.max_tool_calls,
        "max_total_tokens": limits.max_total_tokens,
        "max_cost_minor_units": limits.max_cost_minor_units,
        "currency": limits.currency,
        "max_duration_ms": limits.max_duration_ms,
        "deadline_ms": limits.deadline_ms,
        "pricing_policy_hash": spec.pricing_policy_hash,
        "credential_revision_id": None,
    }
    values.update(changes)
    return ProviderExecutionSelection.create(**values)


class ProviderRuntimeCatalogTests(unittest.TestCase):
    def test_spec_catalog_selection_and_resolution_are_canonical_and_copy_isolated(self) -> None:
        spec = _spec()
        catalog = _catalog(spec)
        selection = _selection(catalog=catalog, spec=spec)
        resolved = catalog.resolve(selection)

        self.assertRegex(spec.content_hash, r"^[0-9a-f]{64}$")
        self.assertRegex(catalog.catalog_hash, r"^[0-9a-f]{64}$")
        self.assertRegex(selection.content_hash, r"^[0-9a-f]{64}$")
        self.assertEqual(spec, resolved.spec)
        self.assertEqual(selection, resolved.selection)
        self.assertEqual(
            {
                "id": "worldforge_conformance_provider",
                "revision": 2,
                "content_hash": H1,
            },
            resolved.runtime_binding,
        )

        leaked = catalog.specs[0]
        object.__setattr__(leaked, "provider_id", "forged")
        self.assertEqual("worldforge", catalog.resolve(selection).spec.provider_id)
        returned = resolved.runtime_binding
        returned["id"] = "forged_runtime"
        self.assertEqual(
            "worldforge_conformance_provider",
            catalog.resolve(selection).runtime_binding["id"],
        )

    def test_catalog_rejects_duplicates_aliases_tamper_and_networked_execution(self) -> None:
        spec = _spec()
        with self.assertRaisesRegex(ProviderCatalogError, "provider_catalog_invalid"):
            ProviderRuntimeCatalog.create([spec])
        with self.assertRaisesRegex(ProviderCatalogError, "provider_catalog_duplicate"):
            ProviderRuntimeCatalog.create((spec, spec))

        tampered = dataclasses.replace(spec)
        object.__setattr__(tampered, "content_hash", H0)
        with self.assertRaisesRegex(ProviderCatalogError, "provider_runtime_spec_invalid"):
            ProviderRuntimeCatalog.create((tampered,))

        forged_catalog = dataclasses.replace(_catalog(spec), catalog_hash=H0)
        with self.assertRaisesRegex(ProviderCatalogError, "provider_catalog_invalid"):
            forged_catalog.resolve(_selection(catalog=forged_catalog, spec=spec))

        loopback = _spec(
            runtime_id="loopback_provider",
            network_scope="loopback",
            endpoint_origin="http://127.0.0.1:11434",
            endpoint_policy_hash=H2,
            egress_enforcement_hash=H3,
            telemetry_attestation_hash=H4,
        )
        with self.assertRaisesRegex(ProviderCatalogError, "provider_runtime_unavailable"):
            ProviderRuntimeCatalog.create((loopback,))

    def test_catalog_rejects_every_production_eligible_runtime_as_unavailable(self) -> None:
        production_specs = (
            _spec(production_eligible=True),
            _spec(
                runtime_id="loopback_provider",
                network_scope="loopback",
                endpoint_origin="http://127.0.0.1:11434",
                endpoint_policy_hash=H2,
                egress_enforcement_hash=H3,
                telemetry_attestation_hash=H4,
                production_eligible=True,
            ),
            _spec(
                runtime_id="cloud_provider",
                deployment_class="cloud",
                network_scope="internet",
                endpoint_origin="https://api.example.test:443",
                endpoint_policy_hash=H2,
                egress_enforcement_hash=H3,
                telemetry_attestation_hash=H4,
                pricing_policy_hash=H5,
                pricing_currency="USD",
                credential_requirement_hash=H6,
                production_eligible=True,
            ),
        )
        for spec in production_specs:
            with self.subTest(network_scope=spec.network_scope):
                with self.assertRaisesRegex(
                    ProviderCatalogError,
                    "provider_runtime_unavailable",
                ):
                    ProviderRuntimeCatalog.create((spec,))

        tampered = dataclasses.replace(_spec())
        object.__setattr__(tampered, "production_eligible", True)
        with self.assertRaisesRegex(ProviderCatalogError, "provider_runtime_unavailable"):
            ProviderRuntimeCatalog.create((tampered,))

        source = _spec()
        catalog = ProviderRuntimeCatalog.create((source,))
        object.__setattr__(source, "production_eligible", True)
        self.assertFalse(catalog.specs[0].production_eligible)

        corrupted_catalog = ProviderRuntimeCatalog.create((_spec(),))
        internal_spec = object.__getattribute__(corrupted_catalog, "_entries")[0]
        object.__setattr__(internal_spec, "production_eligible", True)
        with self.assertRaisesRegex(ProviderCatalogError, "provider_runtime_unavailable"):
            corrupted_catalog.snapshot()

    def test_network_cross_fields_and_endpoint_forms_fail_closed(self) -> None:
        invalid = (
            {"runtime_revision": True},
            {"redirects_disabled": 1},
            {"supported_platforms": ["linux"]},
            {"production_eligible": 0},
            {"network_scope": "none", "endpoint_origin": "http://127.0.0.1:1"},
            {
                "network_scope": "loopback",
                "endpoint_origin": "http://localhost:11434",
                "endpoint_policy_hash": H2,
                "egress_enforcement_hash": H3,
                "telemetry_attestation_hash": H4,
            },
            {
                "network_scope": "loopback",
                "endpoint_origin": "http://127.0.0.1:11434?query=value",
                "endpoint_policy_hash": H2,
                "egress_enforcement_hash": H3,
                "telemetry_attestation_hash": H4,
            },
            {
                "network_scope": "loopback",
                "endpoint_origin": "http://127.0.0.1:11434#fragment",
                "endpoint_policy_hash": H2,
                "egress_enforcement_hash": H3,
                "telemetry_attestation_hash": H4,
            },
            {
                "network_scope": "loopback",
                "endpoint_origin": "http://*:11434",
                "endpoint_policy_hash": H2,
                "egress_enforcement_hash": H3,
                "telemetry_attestation_hash": H4,
            },
            {
                "network_scope": "loopback",
                "endpoint_origin": "http://127.0.0.1:11434",
                "endpoint_policy_hash": H2,
                "egress_enforcement_hash": H3,
                "telemetry_attestation_hash": H4,
                "redirects_disabled": False,
            },
            {
                "network_scope": "loopback",
                "endpoint_origin": "http://0.0.0.0:11434",
                "endpoint_policy_hash": H2,
                "egress_enforcement_hash": H3,
                "telemetry_attestation_hash": H4,
            },
            {
                "network_scope": "loopback",
                "endpoint_origin": "http://user@127.0.0.1:11434",
                "endpoint_policy_hash": H2,
                "egress_enforcement_hash": H3,
                "telemetry_attestation_hash": H4,
            },
            {
                "network_scope": "loopback",
                "endpoint_origin": "http://127.0.0.1:11434/path",
                "endpoint_policy_hash": H2,
                "egress_enforcement_hash": H3,
                "telemetry_attestation_hash": H4,
            },
            {
                "network_scope": "internet",
                "deployment_class": "cloud",
                "endpoint_origin": "http://api.example.test:443",
                "endpoint_policy_hash": H2,
                "egress_enforcement_hash": H3,
                "telemetry_attestation_hash": H4,
                "pricing_policy_hash": H5,
                "pricing_currency": "USD",
                "credential_requirement_hash": H6,
            },
            {
                "network_scope": "internet",
                "deployment_class": "local",
                "endpoint_origin": "https://api.example.test:443",
                "endpoint_policy_hash": H2,
                "egress_enforcement_hash": H3,
                "telemetry_attestation_hash": H4,
                "pricing_policy_hash": H5,
                "pricing_currency": "USD",
                "credential_requirement_hash": H6,
            },
        )
        for changes in invalid:
            with self.subTest(changes=changes):
                with self.assertRaisesRegex(
                    ProviderCatalogError,
                    "provider_runtime_spec_invalid",
                ):
                    _spec(**changes)

        internet = _spec(
            runtime_id="cloud_provider",
            deployment_class="cloud",
            network_scope="internet",
            endpoint_origin="https://api.example.test:443",
            endpoint_policy_hash=H2,
            egress_enforcement_hash=H3,
            telemetry_attestation_hash=H4,
            pricing_policy_hash=H5,
            pricing_currency="USD",
            credential_requirement_hash=H6,
        )
        self.assertEqual("internet", internet.network_scope)

    def test_selection_binds_exact_facets_and_rejects_hostile_types_or_drift(self) -> None:
        catalog = _catalog()
        selection = _selection(catalog=catalog)
        self.assertEqual(selection, catalog.resolve(selection).selection)

        hostile_cases = (
            {"runtime_revision": True},
            {"disclosed_data_classes": ["private_test_payload"]},
            {"disclosed_data_classes": ("private_test_payload", "private_test_payload")},
            {"credential_revision_id": H1},
            {"max_total_tokens": -1},
            {"currency": "usd"},
        )
        for changes in hostile_cases:
            with self.subTest(changes=changes):
                with self.assertRaisesRegex(
                    ProviderCatalogError,
                    "provider_execution_selection_invalid",
                ):
                    _selection(catalog=catalog, **changes)

        for changes in (
            {"catalog_hash": H0},
            {"spec_hash": H0},
            {"runtime_content_hash": H0},
            {"pricing_policy_hash": H9},
            {"credential_revision_id": "credential_revision_abcdefghijklmnopqrstuvwx23"},
        ):
            with self.subTest(drift=changes):
                candidate = _selection(catalog=catalog, **changes)
                with self.assertRaises(ProviderCatalogError):
                    catalog.resolve(candidate)

        first_revision = _selection(
            catalog=catalog,
            credential_revision_id="credential_revision_abcdefghijklmnopqrstuvwx23",
        )
        second_revision = _selection(
            catalog=catalog,
            credential_revision_id="credential_revision_bcdefghijklmnopqrstuvwxy23",
        )
        self.assertNotEqual(first_revision.content_hash, second_revision.content_hash)

    def test_networked_resolved_selection_requires_exact_pricing_currency_and_cost(self) -> None:
        internet = _spec(
            runtime_id="cloud_provider",
            deployment_class="cloud",
            network_scope="internet",
            endpoint_origin="https://api.example.test:443",
            endpoint_policy_hash=H2,
            egress_enforcement_hash=H3,
            telemetry_attestation_hash=H4,
            pricing_policy_hash=H5,
            pricing_currency="USD",
            credential_requirement_hash=H6,
        )
        selection = _selection(
            catalog_hash=H7,
            spec_hash=internet.content_hash,
            runtime_id=internet.runtime_id,
            runtime_revision=internet.runtime_revision,
            runtime_content_hash=internet.runtime_content_hash,
            pricing_policy_hash=internet.pricing_policy_hash,
            currency="EUR",
            credential_revision_id="credential_revision_abcdefghijklmnopqrstuvwx23",
        )
        forged = ResolvedProviderExecution(H7, internet, selection)
        with self.assertRaisesRegex(
            ProviderGovernanceError,
            "provider_governance_review_invalid",
        ):
            ProviderGovernanceReview.create(
                approval_id="provider_approval_01",
                execution_id="execution_minimal_01",
                activation_hash=H6,
                grant_hash=H7,
                work_order_hash=H8,
                private_input_hash=H4,
                resolved=forged,
            )

    def test_credential_revision_drift_changes_selection_and_review_fingerprints(self) -> None:
        loopback = _spec(
            runtime_id="loopback_provider",
            network_scope="loopback",
            endpoint_origin="http://127.0.0.1:11434",
            endpoint_policy_hash=H2,
            egress_enforcement_hash=H3,
            telemetry_attestation_hash=H4,
            credential_requirement_hash=H5,
        )
        unavailable_catalog = ProviderRuntimeCatalog((loopback,), H7)
        selections = tuple(
            _selection(
                catalog=unavailable_catalog,
                spec=loopback,
                credential_revision_id=revision,
            )
            for revision in (
                "credential_revision_abcdefghijklmnopqrstuvwx23",
                "credential_revision_bcdefghijklmnopqrstuvwxy23",
            )
        )
        reviews = tuple(
            ProviderGovernanceReview.create(
                approval_id="provider_approval_01",
                execution_id="execution_minimal_01",
                activation_hash=H6,
                grant_hash=H7,
                work_order_hash=H8,
                private_input_hash=H4,
                resolved=ResolvedProviderExecution(H7, loopback, selection),
            )
            for selection in selections
        )

        self.assertNotEqual(selections[0].content_hash, selections[1].content_hash)
        self.assertNotEqual(reviews[0].content_hash, reviews[1].content_hash)


class ProviderGovernanceAuthorityTests(unittest.TestCase):
    def test_four_facets_are_echoed_and_checked_by_exact_cas(self) -> None:
        review = _review()
        self.assertEqual(review.selection_hash, review.selection_facet_hash)
        for value in (
            review.destination_facet_hash,
            review.data_facet_hash,
            review.pricing_facet_hash,
        ):
            self.assertRegex(value, r"^[0-9a-f]{64}$")

        authority = InMemoryProviderGovernanceAuthority()
        self.assertEqual(review, authority.prepare(review, expected_generation=0))
        decision = ProviderGovernanceDecision.create(
            review=review,
            reviewer_id="provider_reviewer_01",
            outcome="approved",
            expires_at_ms=5_000,
        )
        for field in (
            "approval_id",
            "execution_id",
            "activation_hash",
            "grant_hash",
            "work_order_hash",
            "private_input_hash",
            "selection_hash",
            "selection_facet_hash",
            "destination_facet_hash",
            "data_facet_hash",
            "pricing_facet_hash",
        ):
            self.assertEqual(getattr(review, field), getattr(decision, field))
        authority.decide(
            decision,
            expected_generation=0,
            expected_review_hash=review.content_hash,
        )
        checked = authority.check(review, now_ms=4_999)
        self.assertEqual(review.selection_hash, checked.selection_hash)
        self.assertEqual(decision.content_hash, checked.decision_hash)
        with self.assertRaisesRegex(ProviderGovernanceError, "provider_approval_expired"):
            authority.check(review, now_ms=5_000)

    def test_deny_revoke_stale_and_concurrent_decision_fail_closed(self) -> None:
        review = _review()
        denied_authority = InMemoryProviderGovernanceAuthority()
        denied_authority.prepare(review, expected_generation=0)
        denied = ProviderGovernanceDecision.create(
            review=review,
            reviewer_id="provider_reviewer_01",
            outcome="denied",
            expires_at_ms=None,
        )
        denied_authority.decide(
            denied,
            expected_generation=0,
            expected_review_hash=review.content_hash,
        )
        with self.assertRaisesRegex(ProviderGovernanceError, "provider_approval_denied"):
            denied_authority.check(review, now_ms=1)

        authority = InMemoryProviderGovernanceAuthority()
        authority.prepare(review, expected_generation=0)
        decisions = tuple(
            ProviderGovernanceDecision.create(
                review=review,
                reviewer_id=reviewer,
                outcome="approved",
                expires_at_ms=5_000,
            )
            for reviewer in ("provider_reviewer_first", "provider_reviewer_second")
        )
        barrier = threading.Barrier(3)
        outcomes: list[str] = []

        def decide(value: ProviderGovernanceDecision) -> None:
            barrier.wait()
            try:
                authority.decide(
                    value,
                    expected_generation=0,
                    expected_review_hash=review.content_hash,
                )
            except ProviderGovernanceError as exc:
                outcomes.append(exc.reason_code)
            else:
                outcomes.append("approved")

        threads = [threading.Thread(target=decide, args=(value,)) for value in decisions]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join(timeout=2)
        self.assertCountEqual(("approved", "provider_approval_stale"), outcomes)

        snapshot = authority.snapshot(review)
        assert snapshot.decision_hash is not None
        authority.revoke(
            review.approval_id,
            expected_generation=1,
            expected_decision_hash=snapshot.decision_hash,
        )
        with self.assertRaisesRegex(ProviderGovernanceError, "provider_approval_revoked"):
            authority.check_snapshot(review, snapshot, now_ms=1)
        with self.assertRaisesRegex(ProviderGovernanceError, "provider_approval_stale"):
            authority.revoke(
                review.approval_id,
                expected_generation=1,
                expected_decision_hash=H0,
            )

    def test_facet_tamper_and_detached_snapshot_mutation_cannot_change_authority(self) -> None:
        review = _review()
        authority = InMemoryProviderGovernanceAuthority()
        authority.prepare(review, expected_generation=0)
        decision = ProviderGovernanceDecision.create(
            review=review,
            reviewer_id="provider_reviewer_01",
            outcome="approved",
            expires_at_ms=5_000,
        )
        forged = dataclasses.replace(decision)
        object.__setattr__(forged, "data_facet_hash", H0)
        with self.assertRaisesRegex(
            ProviderGovernanceError,
            "provider_governance_decision_invalid",
        ):
            authority.decide(
                forged,
                expected_generation=0,
                expected_review_hash=review.content_hash,
            )

        authority.decide(
            decision,
            expected_generation=0,
            expected_review_hash=review.content_hash,
        )
        leaked = authority.snapshot(review)
        assert leaked.current_decision is not None
        object.__setattr__(leaked.current_decision, "reviewer_id", "forged_reviewer")
        fresh = authority.snapshot(review)
        assert fresh.current_decision is not None
        self.assertEqual("provider_reviewer_01", fresh.current_decision.reviewer_id)


class ProviderGovernanceKernelTests(unittest.TestCase):
    def _kernel(
        self,
        provider: FakeProvider,
        *,
        broker: CapabilityBroker | None = None,
        journal: FakeJournal | None = None,
        clock: FakeClock | None = None,
        cancellation: FakeCancellation | None = None,
        authority: InMemoryProviderGovernanceAuthority | None = None,
    ):
        broker = CapabilityBroker() if broker is None else broker
        journal = FakeJournal() if journal is None else journal
        clock = FakeClock() if clock is None else clock
        cancellation = FakeCancellation() if cancellation is None else cancellation
        authority = InMemoryProviderGovernanceAuthority() if authority is None else authority
        kernel = AgentExecutionKernel(
            provider=provider,
            broker=broker,
            journal=journal,
            clock=clock,
            cancellation=cancellation,
            provider_catalog=fixed_provider_catalog(),
            provider_governance_authority=authority,
        )
        return kernel, broker, journal, authority

    def _request(self, broker: CapabilityBroker, **changes: object):
        activation, grant = _documents(capabilities=[], tools=[])
        request = _request(activation, grant)
        selection = _execution_selection(request, broker, **changes)
        return replace(
            request,
            provider_approval_id="provider_approval_01",
            provider_selection=selection,
        )

    def _approve(
        self,
        kernel: AgentExecutionKernel,
        authority: InMemoryProviderGovernanceAuthority,
        request,
    ) -> ProviderGovernanceDecision:
        review = kernel.prepare_provider_governance_review(request)
        decision = ProviderGovernanceDecision.create(
            review=review,
            reviewer_id="provider_reviewer_01",
            outcome="approved",
            expires_at_ms=5_000,
        )
        return authority.decide(
            decision,
            expected_generation=0,
            expected_review_hash=review.content_hash,
        )

    def test_default_supervisor_binds_conformance_in_closed_nonproduction_catalog(self) -> None:
        spec = fixed_runtime_spec()
        probe = runtime_spec(_CodeOwnedRuntimeKey.DETERMINISTIC_PROBE)
        catalog = fixed_provider_catalog()
        supervisor = OneShotProviderSupervisor(turn_timeout_ms=1_000)
        self.assertEqual("none", spec.network_scope)
        self.assertFalse(spec.production_eligible)
        self.assertEqual(spec.runtime_binding, supervisor.runtime_binding)
        self.assertEqual(spec, supervisor.runtime_spec)
        self.assertEqual((spec, probe), catalog.specs)

        leaked = supervisor.runtime_spec
        object.__setattr__(leaked, "model_id", "forged")
        self.assertEqual("conformance", supervisor.runtime_spec.model_id)

    def test_kernel_rejects_any_catalog_other_than_the_closed_code_owned_catalog(self) -> None:
        fixed = fixed_runtime_spec()
        values = {
            field: getattr(fixed, field)
            for field in fixed.__dataclass_fields__
            if field != "content_hash"
        }
        values["model_id"] = "alternate_conformance"
        alternate = ProviderRuntimeSpec.create(**values)
        alternate_catalog = ProviderRuntimeCatalog.create((alternate,))
        journal = FakeJournal()
        with self.assertRaisesRegex(KernelError, "provider_catalog_invalid"):
            AgentExecutionKernel(
                provider=FakeProvider([]),
                broker=CapabilityBroker(),
                journal=journal,
                clock=FakeClock(),
                cancellation=FakeCancellation(),
                provider_catalog=alternate_catalog,
                provider_governance_authority=InMemoryProviderGovernanceAuthority(),
            )
        self.assertEqual([], journal.operations)

    def test_missing_provider_approval_has_no_provider_or_broker_effects(self) -> None:
        provider = FakeProvider([ProviderTurnResult("must_not_run", _usage(), completed=True)])

        class ObservingBroker(CapabilityBroker):
            def __init__(self) -> None:
                super().__init__()
                self.activation_calls = 0

            def activate(self, execution_id):
                self.activation_calls += 1
                return super().activate(execution_id)

        broker = ObservingBroker()
        kernel, _, journal, _ = self._kernel(provider, broker=broker)
        result = kernel.execute(self._request(broker))
        self.assertEqual("failed", result.outcome)
        self.assertEqual(["provider_failed"], result.receipt["failure_codes"])
        self.assertEqual([], provider.requests)
        self.assertEqual(0, broker.activation_calls)
        self.assertEqual(["begin", "finalize"], journal.operations)

    def test_exact_approved_snapshot_executes_and_decision_during_begin_is_not_adopted(
        self,
    ) -> None:
        provider = FakeProvider([ProviderTurnResult("approved", _usage(), completed=True)])
        kernel, broker, journal, authority = self._kernel(provider)
        request = self._request(broker)
        self._approve(kernel, authority, request)
        result = kernel.execute(request)
        self.assertEqual("succeeded", result.outcome)
        self.assertEqual("approved", result.private_output)
        self.assertEqual(1, len(provider.requests))

        late_provider = FakeProvider([ProviderTurnResult("must_not_run", _usage(), completed=True)])
        late_authority = InMemoryProviderGovernanceAuthority()
        holder: dict[str, object] = {}

        class DecidingJournal(FakeJournal):
            def begin_execution(self, *args, **kwargs):
                result = super().begin_execution(*args, **kwargs)
                review = holder["review"]
                decision = ProviderGovernanceDecision.create(
                    review=review,
                    reviewer_id="provider_reviewer_late",
                    outcome="approved",
                    expires_at_ms=5_000,
                )
                late_authority.decide(
                    decision,
                    expected_generation=0,
                    expected_review_hash=review.content_hash,
                )
                return result

        late_kernel, late_broker, _, _ = self._kernel(
            late_provider,
            journal=DecidingJournal(),
            authority=late_authority,
        )
        late_request = self._request(late_broker)
        holder["review"] = late_kernel.prepare_provider_governance_review(late_request)
        late_result = late_kernel.execute(late_request)
        self.assertEqual("failed", late_result.outcome)
        self.assertEqual(["provider_failed"], late_result.receipt["failure_codes"])
        self.assertEqual([], late_provider.requests)

    def test_selection_and_each_governance_drift_changes_private_fingerprint(self) -> None:
        fingerprints: list[str] = []
        for changes in (
            {},
            {"non_secret_config_hash": H6},
            {"disclosure_plan_hash": H7},
            {"pricing_policy_hash": None, "max_total_tokens": 99},
        ):
            provider = FakeProvider([])
            kernel, broker, journal, _ = self._kernel(provider)
            request = self._request(broker, **changes)
            result = kernel.execute(request)
            self.assertEqual(["provider_failed"], result.receipt["failure_codes"])
            fingerprint = journal.begin_calls[0][-1]
            assert fingerprint is not None
            fingerprints.append(fingerprint)
        self.assertEqual(len(fingerprints), len(set(fingerprints)))

    def test_missing_governance_prerequisites_still_bind_exact_selection(self) -> None:
        activation, grant = _documents(capabilities=[], tools=[])
        for missing in ("approval", "catalog", "authority", "all"):
            with self.subTest(missing=missing), tempfile.TemporaryDirectory() as temporary:
                broker = CapabilityBroker()
                base = _request(activation, grant)
                first_selection = _execution_selection(base, broker)
                changed_selection = _execution_selection(
                    base,
                    broker,
                    non_secret_config_hash=H6,
                )
                approval_id = None if missing in {"approval", "all"} else "provider_approval_01"
                first_request = replace(
                    base,
                    provider_approval_id=approval_id,
                    provider_selection=first_selection,
                )
                changed_request = replace(first_request, provider_selection=changed_selection)
                provider = FakeProvider([])
                authority = InMemoryProviderGovernanceAuthority()
                with AgentEventLog(temporary) as journal:
                    kernel = AgentExecutionKernel(
                        provider=provider,
                        broker=broker,
                        journal=journal,
                        clock=FakeClock(),
                        cancellation=FakeCancellation(),
                        provider_catalog=(
                            None if missing in {"catalog", "all"} else fixed_provider_catalog()
                        ),
                        provider_governance_authority=(
                            None if missing in {"authority", "all"} else authority
                        ),
                    )
                    coordinator = AgentExecutionCoordinator(kernel=kernel, event_log=journal)
                    first = coordinator.execute(first_request)
                    duplicate = coordinator.execute(first_request)
                    self.assertEqual("executed", first.disposition)
                    self.assertEqual("existing_terminal", duplicate.disposition)
                    self.assertEqual(["provider_failed"], first.result.receipt["failure_codes"])
                    with self.assertRaisesRegex(KernelError, "journal_begin_ambiguous"):
                        coordinator.execute(changed_request)
                self.assertEqual([], provider.requests)

    def test_governance_presence_and_approval_identifiers_bind_private_fingerprint(self) -> None:
        activation, grant = _documents(capabilities=[], tools=[])
        broker = CapabilityBroker()
        base = _request(activation, grant)
        selection = _execution_selection(base, broker)
        cases = (
            (None, None, None, None),
            ("provider_approval_first", selection, None, None),
            (
                "provider_approval_first",
                selection,
                fixed_provider_catalog(),
                None,
            ),
            (
                "provider_approval_first",
                selection,
                None,
                InMemoryProviderGovernanceAuthority(),
            ),
            (
                "provider_approval_second",
                selection,
                None,
                InMemoryProviderGovernanceAuthority(),
            ),
        )
        fingerprints: list[str] = []
        for approval_id, supplied_selection, catalog, authority in cases:
            journal = FakeJournal()
            kernel = AgentExecutionKernel(
                provider=FakeProvider([]),
                broker=broker,
                journal=journal,
                clock=FakeClock(),
                cancellation=FakeCancellation(),
                provider_catalog=catalog,
                provider_governance_authority=authority,
            )
            result = kernel.execute(
                replace(
                    base,
                    provider_approval_id=approval_id,
                    provider_selection=supplied_selection,
                )
            )
            self.assertEqual(["provider_failed"], result.receipt["failure_codes"])
            fingerprint = journal.begin_calls[0][-1]
            assert fingerprint is not None
            fingerprints.append(fingerprint)
        self.assertEqual(len(fingerprints), len(set(fingerprints)))

    def test_invalid_selection_is_rejected_before_durable_begin_when_authority_is_absent(
        self,
    ) -> None:
        activation, grant = _documents(capabilities=[], tools=[])
        broker = CapabilityBroker()
        request = _request(activation, grant)
        selection = _execution_selection(request, broker)
        object.__setattr__(selection, "content_hash", H0)
        journal = FakeJournal()
        kernel = AgentExecutionKernel(
            provider=FakeProvider([]),
            broker=broker,
            journal=journal,
            clock=FakeClock(),
            cancellation=FakeCancellation(),
            provider_catalog=None,
            provider_governance_authority=None,
        )
        with self.assertRaisesRegex(KernelError, "provider_execution_selection_invalid"):
            kernel.execute(replace(request, provider_selection=selection))
        self.assertEqual([], journal.operations)

    def test_revocation_and_cancellation_precedence_are_parent_owned(self) -> None:
        provider = FakeProvider([ProviderTurnResult("must_not_run", _usage(), completed=True)])
        kernel, broker, _, authority = self._kernel(
            provider,
            cancellation=FakeCancellation(cancel_on_check=2),
        )
        request = self._request(broker)
        decision = self._approve(kernel, authority, request)
        authority.revoke(
            request.provider_approval_id,
            expected_generation=1,
            expected_decision_hash=decision.content_hash,
        )
        result = kernel.execute(request)
        self.assertEqual("cancelled", result.outcome)
        self.assertEqual(["execution_cancelled"], result.receipt["failure_codes"])
        self.assertEqual([], provider.requests)

    def test_revoked_authority_has_zero_provider_and_broker_effects(self) -> None:
        class ObservingBroker(CapabilityBroker):
            def __init__(self) -> None:
                super().__init__()
                self.activation_calls = 0

            def activate(self, execution_id):
                self.activation_calls += 1
                return super().activate(execution_id)

        provider = FakeProvider([ProviderTurnResult("must_not_run", _usage(), completed=True)])
        broker = ObservingBroker()
        kernel, _, journal, authority = self._kernel(provider, broker=broker)
        request = self._request(broker)
        decision = self._approve(kernel, authority, request)
        authority.revoke(
            request.provider_approval_id,
            expected_generation=1,
            expected_decision_hash=decision.content_hash,
        )

        result = kernel.execute(request)
        self.assertEqual("failed", result.outcome)
        self.assertEqual(["provider_failed"], result.receipt["failure_codes"])
        self.assertEqual([], provider.requests)
        self.assertEqual(0, broker.activation_calls)
        self.assertEqual(["begin", "finalize"], journal.operations)

    def test_runtime_precedes_provider_authority_check(self) -> None:
        authority = InMemoryProviderGovernanceAuthority()
        approving_provider = FakeProvider([])
        approving_kernel, broker, _, _ = self._kernel(
            approving_provider,
            authority=authority,
        )
        request = self._request(broker)
        self._approve(approving_kernel, authority, request)
        calls: list[str] = []
        original_check = authority.check_snapshot

        def observed_check(*args, **kwargs):
            calls.append("check")
            return original_check(*args, **kwargs)

        authority.check_snapshot = observed_check  # type: ignore[method-assign]
        mismatch_provider = FakeProvider(
            [ProviderTurnResult("must_not_run", _usage(), completed=True)],
            runtime_binding={"id": "other_runtime", "revision": 1, "content_hash": H0},
        )
        mismatch_kernel, _, _, _ = self._kernel(
            mismatch_provider,
            broker=broker,
            authority=authority,
        )
        result = mismatch_kernel.execute(request)
        self.assertEqual("failed", result.outcome)
        self.assertEqual(["provider_failed"], result.receipt["failure_codes"])
        self.assertEqual([], calls)
        self.assertEqual([], mismatch_provider.requests)

    def test_usage_and_budget_are_sealed_before_post_provider_revocation(self) -> None:
        def revoking_action(authority, approval_id, decision_hash, usage):
            def action(_request):
                authority.revoke(
                    approval_id,
                    expected_generation=1,
                    expected_decision_hash=decision_hash,
                )
                return ProviderTurnResult("not_public", usage, completed=True)

            return action

        cases = (
            (_usage(), "provider_failed"),
            (_usage(input_tokens=100, output_tokens=1), "token_budget_exceeded"),
        )
        for usage, expected_failure in cases:
            with self.subTest(expected_failure=expected_failure):
                provider = FakeProvider([])
                kernel, broker, _, authority = self._kernel(provider)
                request = self._request(broker)
                decision = self._approve(kernel, authority, request)
                provider.script.append(
                    revoking_action(
                        authority,
                        request.provider_approval_id,
                        decision.content_hash,
                        usage,
                    )
                )
                result = kernel.execute(request)
                self.assertEqual("failed", result.outcome)
                self.assertEqual([expected_failure], result.receipt["failure_codes"])
                self.assertEqual(usage.input_tokens, result.receipt["usage"]["input_tokens"])
                self.assertEqual(usage.output_tokens, result.receipt["usage"]["output_tokens"])
                self.assertEqual(
                    usage.cost_minor_units,
                    result.receipt["usage"]["cost_minor_units"],
                )

    def test_credentials_are_identity_only_and_never_enter_worker_or_public_evidence(self) -> None:
        secret = "CREDENTIAL_SECRET_SENTINEL_42"
        provider = FakeProvider([RuntimeError(secret)])
        with tempfile.TemporaryDirectory() as temporary, AgentEventLog(temporary) as journal:
            kernel, broker, _, authority = self._kernel(provider, journal=journal)
            request = self._request(broker)
            self._approve(kernel, authority, request)
            result = kernel.execute(request)
            self.assertEqual(["provider_failed"], result.receipt["failure_codes"])
            serialized = repr(
                {
                    "requests": provider.requests,
                    "receipt": result.receipt,
                    "events": result.events,
                    "private_output": result.private_output,
                }
            )
            for sentinel in (
                secret,
                "provider_approval_01",
                "provider_reviewer_01",
                "reviewer_id",
                "approval_id",
                "credential_revision_id",
            ):
                self.assertNotIn(sentinel, serialized)
                encoded = sentinel.encode("utf-8")
                for suffix in ("", "-wal", "-shm", "-journal"):
                    path = f"{journal.database_path}{suffix}"
                    if os.path.exists(path):
                        with open(path, "rb") as stream:
                            self.assertNotIn(encoded, stream.read())

    def test_exact_terminal_duplicate_remains_evidence_only_after_revocation(self) -> None:
        provider = FakeProvider([ProviderTurnResult("first", _usage(), completed=True)])
        with tempfile.TemporaryDirectory() as temporary, AgentEventLog(temporary) as journal:
            kernel, broker, _, authority = self._kernel(provider, journal=journal)
            request = self._request(broker)
            decision = self._approve(kernel, authority, request)
            coordinator = AgentExecutionCoordinator(kernel=kernel, event_log=journal)
            first = coordinator.execute(request)
            self.assertEqual("executed", first.disposition)
            self.assertEqual(1, len(provider.requests))
            authority.revoke(
                request.provider_approval_id,
                expected_generation=1,
                expected_decision_hash=decision.content_hash,
            )
            duplicate = coordinator.execute(request)
            self.assertEqual("existing_terminal", duplicate.disposition)
            self.assertEqual(first.records, duplicate.records)
            self.assertEqual(1, len(provider.requests))


@unittest.skipUnless(sys.platform.startswith("linux"), "provider containment is Linux-only")
class NativeProviderGovernanceTests(unittest.TestCase):
    def test_revocation_stops_blocked_worker_and_proves_cleanup(self) -> None:
        class RealtimeClock:
            def __init__(self) -> None:
                self.origin = time.monotonic()

            def now_ms(self) -> int:
                return 1_000 + int((time.monotonic() - self.origin) * 1_000)

        activation, grant = _documents(capabilities=[], tools=[])
        request = replace(
            _request(
                activation,
                grant,
                max_duration_ms=5_000,
                deadline_ms=10_000,
            ),
            private_input={
                "__worldforge_conformance__": {
                    "action": "sleep",
                    "milliseconds": 3_000,
                }
            },
        )
        supervisor = OneShotProviderSupervisor(turn_timeout_ms=5_000)
        broker = CapabilityBroker()
        authority = InMemoryProviderGovernanceAuthority()
        kernel = AgentExecutionKernel(
            provider=supervisor,
            broker=broker,
            journal=FakeJournal(),
            clock=RealtimeClock(),
            cancellation=FakeCancellation(),
            provider_catalog=fixed_provider_catalog(),
            provider_governance_authority=authority,
        )
        request = replace(
            request,
            provider_approval_id="provider_approval_blocked_01",
            provider_selection=_execution_selection(request, broker),
        )
        review = kernel.prepare_provider_governance_review(request)
        decision = ProviderGovernanceDecision.create(
            review=review,
            reviewer_id="provider_reviewer_01",
            outcome="approved",
            expires_at_ms=10_000,
        )
        authority.decide(
            decision,
            expected_generation=0,
            expected_review_hash=review.content_hash,
        )
        captured: dict[str, object] = {}

        def execute() -> None:
            try:
                captured["result"] = kernel.execute(request)
            except BaseException as exc:
                captured["error"] = exc

        thread = threading.Thread(target=execute)
        started = time.monotonic()
        thread.start()
        deadline = time.monotonic() + 2
        while supervisor.active_worker_pid is None and time.monotonic() < deadline:
            time.sleep(0.01)
        worker_pid = supervisor.active_worker_pid
        self.assertIsNotNone(worker_pid)
        authority.revoke(
            review.approval_id,
            expected_generation=1,
            expected_decision_hash=decision.content_hash,
        )
        thread.join(timeout=3)
        self.assertFalse(thread.is_alive())
        self.assertNotIn("error", captured)
        result = captured["result"]
        self.assertEqual("failed", result.outcome)
        self.assertEqual(["provider_failed"], result.receipt["failure_codes"])
        self.assertLess(time.monotonic() - started, 3)
        self.assertEqual(1, supervisor.spawn_count)
        self.assertIsNone(supervisor.active_worker_pid)
        self.assertIsNone(supervisor.active_broker_pid)
        self.assertFalse(os.path.exists(f"/proc/{worker_pid}"))


if __name__ == "__main__":
    unittest.main()
