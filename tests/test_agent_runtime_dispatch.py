from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import sys
import tempfile
import unittest
from dataclasses import replace
from unittest import mock

from tests.agent_harness_fakes import FakeCancellation, FakeClock, FakeJournal
from tests.test_agent_execution_kernel import _documents, _request, _usage
from tests.test_agent_provider_governance import _execution_selection
from tests.test_agent_worker_supervisor import _control, _turn_request
from worldforge.agent_harness import (
    AgentEventLog,
    AgentExecutionCoordinator,
    AgentExecutionKernel,
    CapabilityBroker,
    KernelError,
)
from worldforge.agent_harness import process_supervisor as process_supervisor_module
from worldforge.agent_harness import provider_egress as provider_egress_module
from worldforge.agent_harness import supervisor as supervisor_module
from worldforge.agent_harness import worker as worker_module
from worldforge.agent_harness import worker_registry as worker_registry_module
from worldforge.agent_harness.ports import ProviderTurnResult
from worldforge.agent_harness.process_supervisor import (
    ProviderBoundaryFailure,
    fixed_worker_command,
)
from worldforge.agent_harness.provider_catalog import (
    ProviderCatalogError,
    ProviderExecutionSelection,
    ProviderRuntimeCatalog,
    ProviderRuntimeSpec,
)
from worldforge.agent_harness.provider_governance import (
    InMemoryProviderGovernanceAuthority,
    ProviderGovernanceDecision,
    ProviderGovernanceReview,
)
from worldforge.agent_harness.supervisor import OneShotProviderSupervisor
from worldforge.agent_harness.worker_protocol import (
    WorkerProtocolError,
    build_request_frame,
    build_result_frame,
    parse_request_frame,
    parse_result_frame,
)
from worldforge.agent_harness.worker_registry import (
    _CodeOwnedRuntimeKey,
    code_owned_provider_catalog,
    fixed_provider_catalog,
    fixed_runtime_identity,
    fixed_runtime_spec,
    runtime_entry,
    runtime_entry_for_selection,
    runtime_environment,
    runtime_identity,
    runtime_spec,
)
from worldforge.agent_harness_contracts import canonical_agent_harness_hash

H0 = "0" * 64
H1 = "1" * 64
H2 = "2" * 64
H3 = "3" * 64
H4 = "4" * 64
H5 = "5" * 64


def _selection(key: _CodeOwnedRuntimeKey) -> ProviderExecutionSelection:
    catalog = code_owned_provider_catalog()
    spec = runtime_spec(key)
    return ProviderExecutionSelection.create(
        catalog_hash=catalog.catalog_hash,
        spec_hash=spec.content_hash,
        runtime_id=spec.runtime_id,
        runtime_revision=spec.runtime_revision,
        runtime_content_hash=spec.runtime_content_hash,
        non_secret_config_hash=H1,
        disclosure_plan_hash=H2,
        disclosed_data_classes=("private_test_payload",),
        base_payload_hash=H3,
        tool_catalog_hash=H4,
        max_turns=4,
        max_tool_calls=2,
        max_total_tokens=100,
        max_cost_minor_units=10,
        currency="USD",
        max_duration_ms=1_000,
        deadline_ms=2_000,
        pricing_policy_hash=None,
        credential_revision_id=None,
    )


def _documents_for_runtime(
    key: _CodeOwnedRuntimeKey,
) -> tuple[dict[str, object], dict[str, object]]:
    activation, grant = _documents(capabilities=[], tools=[])
    binding = runtime_identity(key)
    activation["runtime"] = binding
    activation["content_hash"] = canonical_agent_harness_hash(activation)
    grant["runtime"] = binding
    grant["activation"] = {
        "id": activation["activation_id"],
        "content_hash": activation["content_hash"],
    }
    grant["content_hash"] = canonical_agent_harness_hash(grant)
    return activation, grant


class ConformanceRuntimeApprovalTests(unittest.TestCase):
    def test_existing_conformance_template_bytes_and_hash_are_pinned(self) -> None:
        encoded = worker_module.WORKER_BOOTSTRAP_TEMPLATE.encode("utf-8")

        self.assertEqual(13_446, len(encoded))
        self.assertEqual(
            "62edb8058126c106eba24b457a2f2be232c952e4389584ad1bd5a4d3234aff0c",
            hashlib.sha256(encoded).hexdigest(),
        )
        self.assertEqual(
            "62edb8058126c106eba24b457a2f2be232c952e4389584ad1bd5a4d3234aff0c",
            fixed_runtime_identity()["content_hash"],
        )


class CodeOwnedRuntimeRegistryTests(unittest.TestCase):
    def test_registry_captures_factory_once_and_never_exposes_or_reinvokes_it(self) -> None:
        key = _CodeOwnedRuntimeKey.CONFORMANCE
        artifact = worker_module._conformance_worker_artifact()
        alternate = worker_module._deterministic_probe_worker_artifact()
        calls: list[int] = []

        def alternating_factory():
            calls.append(len(calls) + 1)
            return artifact if len(calls) == 1 else alternate

        entry = worker_registry_module._build_entry(key, alternating_factory)
        self.assertEqual([1], calls)
        self.assertEqual(entry, worker_registry_module._validate_entry(entry))
        self.assertEqual([1], calls)
        self.assertFalse(hasattr(entry, "artifact_factory"))
        self.assertEqual(artifact, entry.artifact)

        expected_source = provider_egress_module._provider_worker_launcher_source(
            runtime_entry(key).artifact.bootstrap_source
        )
        with mock.patch.object(
            worker_module,
            "_conformance_worker_artifact",
            side_effect=AssertionError("factory was re-invoked"),
        ):
            self.assertEqual(expected_source, fixed_worker_command(key)[8])
            self.assertEqual(artifact, worker_registry_module.runtime_artifact(key))

    def test_catalog_has_exactly_two_distinct_immutable_offline_entries(self) -> None:
        self.assertEqual(
            {
                _CodeOwnedRuntimeKey.CONFORMANCE,
                _CodeOwnedRuntimeKey.DETERMINISTIC_PROBE,
            },
            set(_CodeOwnedRuntimeKey),
        )
        entries = tuple(runtime_entry(key) for key in _CodeOwnedRuntimeKey)
        self.assertEqual(2, len(entries))
        self.assertEqual(
            {
                "worldforge_conformance_provider",
                "worldforge_deterministic_probe_provider",
            },
            {entry.identifier for entry in entries},
        )
        self.assertEqual(2, len({entry.content_hash for entry in entries}))
        self.assertEqual(2, len({entry.spec.content_hash for entry in entries}))
        self.assertTrue(all(entry.protocol_version == 1 for entry in entries))
        self.assertTrue(all(entry.spec.network_scope == "none" for entry in entries))
        self.assertTrue(all(not entry.spec.production_eligible for entry in entries))
        self.assertEqual(
            tuple(entry.spec for entry in entries),
            code_owned_provider_catalog().specs,
        )

        leaked = entries[1]
        object.__setattr__(leaked.spec, "model_id", "caller_forged")
        self.assertEqual(
            "deterministic_probe",
            runtime_entry(_CodeOwnedRuntimeKey.DETERMINISTIC_PROBE).spec.model_id,
        )

    def test_entries_bind_exact_frozen_artifact_hash_spec_and_closed_environment(self) -> None:
        for key in _CodeOwnedRuntimeKey:
            with self.subTest(key=key):
                entry = runtime_entry(key)
                artifact = entry.artifact
                self.assertEqual(entry.identifier, artifact.identifier)
                self.assertEqual(entry.revision, artifact.revision)
                self.assertEqual(entry.protocol_version, artifact.protocol_version)
                self.assertEqual(entry.bootstrap_template, artifact.bootstrap_template)
                self.assertEqual(entry.bootstrap_source, artifact.bootstrap_source)
                self.assertEqual(entry.content_hash, artifact.content_hash)
                self.assertEqual(
                    entry.content_hash,
                    hashlib.sha256(entry.bootstrap_template.encode("utf-8")).hexdigest(),
                )
                self.assertEqual(
                    1,
                    entry.bootstrap_template.count(worker_module.RUNTIME_CONTENT_HASH_TOKEN),
                )
                self.assertNotIn(worker_module.RUNTIME_CONTENT_HASH_TOKEN, entry.bootstrap_source)
                self.assertEqual(1, entry.bootstrap_source.count(entry.content_hash))
                self.assertEqual(entry.runtime_binding, entry.spec.runtime_binding)
                self.assertEqual(
                    {
                        "ANTHROPIC_DISABLE_TELEMETRY": "1",
                        "DO_NOT_TRACK": "1",
                        "HF_HUB_DISABLE_TELEMETRY": "1",
                        "OPENAI_DISABLE_TELEMETRY": "1",
                        "PYTHONDONTWRITEBYTECODE": "1",
                        "PYTHONIOENCODING": "utf-8",
                        "PYTHONUTF8": "1",
                    },
                    runtime_environment(key),
                )

    def test_artifact_tamper_and_registry_aliases_fail_closed(self) -> None:
        key = _CodeOwnedRuntimeKey.CONFORMANCE
        entry = runtime_entry(key)
        forged_artifact = dataclasses.replace(
            entry.artifact,
            identifier="worldforge_deterministic_probe_provider",
        )
        forged_entry = dataclasses.replace(entry, artifact=forged_artifact)
        original = worker_registry_module._RUNTIME_ENTRIES
        replacement = tuple(
            forged_entry if candidate.key is key else candidate for candidate in original
        )
        with mock.patch.object(worker_registry_module, "_RUNTIME_ENTRIES", replacement):
            with self.assertRaisesRegex(RuntimeError, "code_owned_runtime_registry_invalid"):
                runtime_entry(key)

        self.assertEqual(code_owned_provider_catalog(), fixed_provider_catalog())
        leaked_catalog = fixed_provider_catalog()
        object.__setattr__(leaked_catalog._entries[0], "model_id", "caller_forged")
        self.assertEqual(
            "conformance",
            code_owned_provider_catalog().resolve(_selection(key)).spec.model_id,
        )
        self.assertEqual(fixed_runtime_spec(), runtime_spec(key))
        self.assertEqual(fixed_runtime_identity(), runtime_identity(key))

    def test_selection_resolves_only_to_the_exact_code_owned_enum_entry(self) -> None:
        for key in _CodeOwnedRuntimeKey:
            selection = _selection(key)
            self.assertIs(key, runtime_entry_for_selection(selection).key)

        old_catalog = ProviderRuntimeCatalog.create((fixed_runtime_spec(),))
        old_selection = dataclasses.replace(
            _selection(_CodeOwnedRuntimeKey.CONFORMANCE),
            catalog_hash=old_catalog.catalog_hash,
        )
        old_selection = ProviderExecutionSelection.create(
            **{
                field: getattr(old_selection, field)
                for field in old_selection.__dataclass_fields__
                if field != "content_hash"
            }
        )
        with self.assertRaisesRegex(ProviderCatalogError, "provider_catalog_mismatch"):
            runtime_entry_for_selection(old_selection)

        forged = dataclasses.replace(_selection(_CodeOwnedRuntimeKey.CONFORMANCE))
        object.__setattr__(forged, "runtime_id", "worldforge_unknown_provider")
        with self.assertRaisesRegex(ProviderCatalogError, "provider_execution_selection_invalid"):
            runtime_entry_for_selection(forged)

    def test_probe_source_contains_no_file_network_sdk_or_dynamic_import_logic(self) -> None:
        source = runtime_entry(_CodeOwnedRuntimeKey.DETERMINISTIC_PROBE).bootstrap_source
        for forbidden in (
            "__import__",
            "connect(",
            "httpx",
            "open(",
            "openai",
            "pathlib",
            "import requests",
            "scandir",
            "socket",
            "subprocess",
            "urllib",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source.lower())


class RuntimeBoundProtocolTests(unittest.TestCase):
    def test_authenticated_frames_remain_v1_and_reject_cross_runtime_parsing(self) -> None:
        request = _turn_request({"probe": "request"})
        key = b"k" * 32
        nonce = "ab" * 32
        conformance = _CodeOwnedRuntimeKey.CONFORMANCE
        probe = _CodeOwnedRuntimeKey.DETERMINISTIC_PROBE
        frame = build_request_frame(request, key=key, nonce=nonce, runtime_key=conformance)
        size = int.from_bytes(frame[:4], "big")
        document = json.loads(frame[4 : 4 + size])
        self.assertEqual(1, document["format_version"])
        self.assertEqual(runtime_identity(conformance), document["runtime"])
        self.assertEqual(
            request,
            parse_request_frame(frame, key=key, runtime_key=conformance).request,
        )
        with self.assertRaisesRegex(WorkerProtocolError, "worker_protocol_runtime_mismatch"):
            parse_request_frame(frame, key=key, runtime_key=probe)

        request_hash = parse_request_frame(
            frame,
            key=key,
            runtime_key=conformance,
        ).request_hash
        result = ProviderTurnResult("bound", _usage(), completed=True)
        result_frame = build_result_frame(
            result,
            key=key,
            nonce=nonce,
            request_hash=request_hash,
            runtime_key=conformance,
        )
        self.assertEqual(
            result,
            parse_result_frame(
                result_frame,
                key=key,
                nonce=nonce,
                request_hash=request_hash,
                runtime_key=conformance,
            ),
        )
        with self.assertRaisesRegex(WorkerProtocolError, "worker_protocol_runtime_mismatch"):
            parse_result_frame(
                result_frame,
                key=key,
                nonce=nonce,
                request_hash=request_hash,
                runtime_key=probe,
            )

    def test_command_is_exact_enum_bound_absolute_python_with_no_injection_surface(self) -> None:
        commands = {key: fixed_worker_command(key) for key in _CodeOwnedRuntimeKey}
        for key, command in commands.items():
            with self.subTest(key=key):
                self.assertEqual(os.path.abspath(sys.executable), command[0])
                self.assertEqual(("-I", "-B", "-S", "-u", "-X", "utf8", "-c"), command[1:8])
                self.assertEqual(
                    provider_egress_module._provider_worker_launcher_source(
                        runtime_entry(key).bootstrap_source
                    ),
                    command[8],
                )
                self.assertIn(runtime_entry(key).identifier, command[8])
                for other in _CodeOwnedRuntimeKey:
                    if other is not key:
                        self.assertNotIn(runtime_entry(other).identifier, command[8])
        self.assertNotEqual(
            commands[_CodeOwnedRuntimeKey.CONFORMANCE][8],
            commands[_CodeOwnedRuntimeKey.DETERMINISTIC_PROBE][8],
        )
        with self.assertRaisesRegex(ProviderBoundaryFailure, "provider_failed"):
            fixed_worker_command("worldforge_deterministic_probe_provider")  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            OneShotProviderSupervisor(runtime_key=_CodeOwnedRuntimeKey.DETERMINISTIC_PROBE)  # type: ignore[call-arg]


@unittest.skipUnless(sys.platform.startswith("linux"), "real containment probe is Linux-only")
class LinuxRuntimeDispatchTests(unittest.TestCase):
    def test_supervisor_runtime_authority_rejects_normal_reassignment_and_deletion(
        self,
    ) -> None:
        supervisor = OneShotProviderSupervisor.for_selection(
            _selection(_CodeOwnedRuntimeKey.DETERMINISTIC_PROBE),
            turn_timeout_ms=2_000,
        )

        replacements = {
            "provider": OneShotProviderSupervisor(turn_timeout_ms=2_000),
            "_authority": object(),
            "_runtime_key": _CodeOwnedRuntimeKey.CONFORMANCE,
            "_process_supervisor": object(),
            "_turn_timeout_ms": 1,
            "turn": lambda *_args, **_kwargs: None,
        }
        for name, value in replacements.items():
            with self.subTest(operation="set", name=name):
                with self.assertRaisesRegex(AttributeError, "authority is immutable"):
                    setattr(supervisor, name, value)
        for name in (
            "_authority",
            "_runtime_key",
            "_process_supervisor",
            "_turn_timeout_ms",
        ):
            with self.subTest(operation="delete", name=name):
                with self.assertRaisesRegex(AttributeError, "authority is immutable"):
                    delattr(supervisor, name)

    def test_construction_freezes_selector_registry_protocol_and_artifact_dispatch(
        self,
    ) -> None:
        key = _CodeOwnedRuntimeKey.DETERMINISTIC_PROBE
        selection = _selection(key)
        supervisor = OneShotProviderSupervisor.for_selection(selection, turn_timeout_ms=2_000)
        frozen_turn = supervisor.turn
        expected_binding = supervisor.runtime_binding
        expected_source = runtime_entry(key).artifact.bootstrap_source

        object.__setattr__(selection, "runtime_id", fixed_runtime_spec().runtime_id)
        object.__setattr__(selection, "runtime_content_hash", fixed_runtime_spec().content_hash)
        supervisor._process_supervisor.execute = mock.Mock(  # type: ignore[method-assign]
            side_effect=AssertionError("process callable was re-read")
        )
        with (
            mock.patch.object(worker_registry_module, "_RUNTIME_ENTRIES", ()),
            mock.patch.object(
                worker_module,
                "_deterministic_probe_worker_artifact",
                side_effect=AssertionError("factory was re-invoked"),
            ),
            mock.patch.object(
                supervisor_module,
                "build_request_frame",
                side_effect=AssertionError("request protocol was re-read"),
            ),
            mock.patch.object(
                supervisor_module,
                "parse_request_frame",
                side_effect=AssertionError("request parser was re-read"),
            ),
            mock.patch.object(
                supervisor_module,
                "parse_result_frame",
                side_effect=AssertionError("result protocol was re-read"),
            ),
            mock.patch.object(
                process_supervisor_module,
                "fixed_worker_command",
                side_effect=AssertionError("worker command was re-read"),
            ),
            mock.patch.object(
                process_supervisor_module,
                "_minimal_environment",
                side_effect=AssertionError("worker environment was re-read"),
            ),
        ):
            result = frozen_turn(
                _turn_request({"probe": "frozen-authority"}),
                boundary=_control(),
            )

        self.assertEqual(expected_binding, supervisor.runtime_binding)
        self.assertEqual(
            "worldforge_deterministic_probe_provider",
            result.private_output["runtime_id"],
        )
        self.assertIn("worldforge_deterministic_probe_provider", expected_source)
        self.assertNotIn("worldforge_conformance_provider", expected_source)
        self.assertEqual(1, supervisor.spawn_count)

    def test_exact_selection_dispatches_probe_then_releases_after_domain_empty(self) -> None:
        key = _CodeOwnedRuntimeKey.DETERMINISTIC_PROBE
        selection = _selection(key)
        supervisor = OneShotProviderSupervisor.for_selection(selection, turn_timeout_ms=2_000)
        result = supervisor.turn(
            _turn_request({"probe": "payload"}),
            boundary=_control(),
        )

        self.assertEqual(runtime_identity(key), supervisor.runtime_binding)
        self.assertEqual(runtime_spec(key), supervisor.runtime_spec)
        self.assertEqual(
            {
                "execution_id": "execution_minimal_01",
                "exposed_tool_count": 0,
                "history_hash": hashlib.sha256(b"[]").hexdigest(),
                "private_input_hash": hashlib.sha256(b'{"probe":"payload"}').hexdigest(),
                "runtime_id": "worldforge_deterministic_probe_provider",
                "tool_summary_count": 0,
                "turn_index": 0,
            },
            result.private_output,
        )
        self.assertEqual(1, supervisor.spawn_count)
        self.assertIsNone(supervisor.active_broker_pid)
        self.assertIsNone(supervisor.active_worker_pid)

    def test_stale_unknown_or_forged_selection_fails_before_process_authority(self) -> None:
        old_catalog = ProviderRuntimeCatalog.create((fixed_runtime_spec(),))
        stale_values = {
            field: getattr(_selection(_CodeOwnedRuntimeKey.CONFORMANCE), field)
            for field in ProviderExecutionSelection.__dataclass_fields__
            if field != "content_hash"
        }
        stale_values["catalog_hash"] = old_catalog.catalog_hash
        stale = ProviderExecutionSelection.create(**stale_values)
        forged = dataclasses.replace(_selection(_CodeOwnedRuntimeKey.CONFORMANCE))
        object.__setattr__(forged, "content_hash", H0)

        with mock.patch(
            "worldforge.agent_harness.supervisor.LinuxProcessSupervisor"
        ) as process_type:
            for selection in (stale, forged):
                with self.subTest(selection=selection):
                    with self.assertRaises(ProviderCatalogError):
                        OneShotProviderSupervisor.for_selection(selection)
            process_type.assert_not_called()

    def test_probe_selection_runs_through_exact_governance_and_duplicate_is_evidence_only(
        self,
    ) -> None:
        key = _CodeOwnedRuntimeKey.DETERMINISTIC_PROBE
        activation, grant = _documents_for_runtime(key)
        broker = CapabilityBroker()
        request = replace(
            _request(activation, grant),
            private_input={"probe": "kernel"},
        )
        catalog = code_owned_provider_catalog()
        selection = _execution_selection(
            request,
            broker,
            catalog=catalog,
            spec=runtime_spec(key),
        )
        request = replace(
            request,
            provider_approval_id="provider_approval_probe_01",
            provider_selection=selection,
        )
        authority = InMemoryProviderGovernanceAuthority()
        provider_selector = dataclasses.replace(selection)
        provider = OneShotProviderSupervisor.for_selection(
            provider_selector,
            turn_timeout_ms=2_000,
        )
        with tempfile.TemporaryDirectory() as temporary, AgentEventLog(temporary) as journal:
            kernel = AgentExecutionKernel(
                provider=provider,
                broker=broker,
                journal=journal,
                clock=FakeClock(),
                cancellation=FakeCancellation(),
                provider_catalog=catalog,
                provider_governance_authority=authority,
            )
            review = kernel.prepare_provider_governance_review(request)
            decision = ProviderGovernanceDecision.create(
                review=review,
                reviewer_id="provider_reviewer_probe_01",
                outcome="approved",
                expires_at_ms=5_000,
            )
            authority.decide(
                decision,
                expected_generation=0,
                expected_review_hash=review.content_hash,
            )
            coordinator = AgentExecutionCoordinator(kernel=kernel, event_log=journal)
            object.__setattr__(provider_selector, "runtime_id", fixed_runtime_spec().runtime_id)
            with (
                mock.patch.object(worker_registry_module, "_RUNTIME_ENTRIES", ()),
                mock.patch.object(
                    worker_module,
                    "_deterministic_probe_worker_artifact",
                    side_effect=AssertionError("factory was re-invoked"),
                ),
            ):
                first = coordinator.execute(request)
                duplicate = coordinator.execute(request)

        self.assertEqual("executed", first.disposition)
        self.assertEqual("succeeded", first.result.outcome)
        self.assertEqual(runtime_identity(key), first.result.receipt["runtime_binding"])
        self.assertEqual(
            "worldforge_deterministic_probe_provider",
            first.result.private_output["runtime_id"],
        )
        self.assertEqual("existing_terminal", duplicate.disposition)
        self.assertEqual(first.records, duplicate.records)
        self.assertEqual(1, provider.spawn_count)

    def test_pending_old_catalog_approval_unknown_and_unavailable_specs_never_spawn(self) -> None:
        provider = OneShotProviderSupervisor(turn_timeout_ms=1_000)
        broker = CapabilityBroker()
        activation, grant = _documents_for_runtime(_CodeOwnedRuntimeKey.CONFORMANCE)
        request = _request(activation, grant)
        exact_selection = _execution_selection(
            request,
            broker,
            catalog=code_owned_provider_catalog(),
            spec=fixed_runtime_spec(),
        )
        old_catalog = ProviderRuntimeCatalog.create((fixed_runtime_spec(),))
        old_values = {
            field: getattr(exact_selection, field)
            for field in exact_selection.__dataclass_fields__
            if field != "content_hash"
        }
        old_values["catalog_hash"] = old_catalog.catalog_hash
        old_selection = ProviderExecutionSelection.create(**old_values)
        authority = InMemoryProviderGovernanceAuthority()
        stale_review = ProviderGovernanceReview.create(
            approval_id="provider_approval_stale_01",
            execution_id=activation["execution_id"],
            activation_hash=activation["content_hash"],
            grant_hash=grant["content_hash"],
            work_order_hash=H4,
            private_input_hash=old_selection.base_payload_hash,
            resolved=old_catalog.resolve(old_selection),
        )
        authority.prepare(stale_review, expected_generation=0)
        stale_decision = ProviderGovernanceDecision.create(
            review=stale_review,
            reviewer_id="provider_reviewer_stale_01",
            outcome="approved",
            expires_at_ms=5_000,
        )
        authority.decide(
            stale_decision,
            expected_generation=0,
            expected_review_hash=stale_review.content_hash,
        )
        journal = FakeJournal()
        kernel = AgentExecutionKernel(
            provider=provider,
            broker=broker,
            journal=journal,
            clock=FakeClock(),
            cancellation=FakeCancellation(),
            provider_catalog=code_owned_provider_catalog(),
            provider_governance_authority=authority,
        )
        stale_request = replace(
            request,
            provider_approval_id="provider_approval_stale_01",
            provider_selection=old_selection,
        )
        with self.assertRaisesRegex(KernelError, "provider_catalog_mismatch"):
            kernel.prepare_provider_governance_review(stale_request)
        self.assertEqual(0, provider.spawn_count)
        self.assertEqual([], journal.operations)

        unknown_values = dict(old_values)
        unknown_values.update(
            catalog_hash=code_owned_provider_catalog().catalog_hash,
            runtime_id="worldforge_unknown_provider",
        )
        unknown_selection = ProviderExecutionSelection.create(**unknown_values)
        unknown_request = replace(
            request,
            provider_approval_id="provider_approval_unknown_01",
            provider_selection=unknown_selection,
        )
        with self.assertRaisesRegex(KernelError, "provider_execution_selection_invalid"):
            kernel.execute(unknown_request)
        self.assertEqual(0, provider.spawn_count)
        self.assertEqual([], journal.operations)

        spec_values = {
            field: getattr(fixed_runtime_spec(), field)
            for field in fixed_runtime_spec().__dataclass_fields__
            if field != "content_hash"
        }
        production = ProviderRuntimeSpec.create(**{**spec_values, "production_eligible": True})
        networked = ProviderRuntimeSpec.create(
            **{
                **spec_values,
                "runtime_id": "worldforge_loopback_probe",
                "network_scope": "loopback",
                "endpoint_origin": "http://127.0.0.1:8080",
                "endpoint_policy_hash": H1,
                "egress_enforcement_hash": H2,
                "telemetry_attestation_hash": H3,
            }
        )
        with self.assertRaisesRegex(ProviderCatalogError, "provider_runtime_unavailable"):
            ProviderRuntimeCatalog.create((production,))
        # Loopback descriptors remain valid policy data.  They become executable
        # only through the exact code-owned gateway catalog captured by a supervisor.
        self.assertEqual(networked, ProviderRuntimeCatalog.create((networked,)).specs[0])
        self.assertEqual(0, provider.spawn_count)


if __name__ == "__main__":
    unittest.main()
