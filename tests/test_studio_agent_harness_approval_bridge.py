from __future__ import annotations

import gc
import sys
import tempfile
import threading
import unittest
from copy import copy, deepcopy
from dataclasses import replace
from pathlib import Path
from weakref import ref

from tests.agent_harness_fakes import (
    FakeCancellation,
    FakeClock,
    FakeJournal,
    FakeProvider,
    FakeTool,
)
from tests.test_agent_execution_kernel import (
    _documents,
    _ProviderAutoApprovingKernel,
    _request,
    _usage,
)
from tests.test_agent_human_approval import _review as _approval_review
from worldforge.agent_harness import AgentEventLog, AgentExecutionCoordinator
from worldforge.agent_harness import approvals as approvals_module
from worldforge.agent_harness import kernel as kernel_module
from worldforge.agent_harness.approvals import ExecutionApprovalDecision
from worldforge.agent_harness.approvals import (
    ApprovalAuthoritySnapshot,
    ApprovalCheck,
    ApprovalError,
    ExecutionApprovalAuthority,
    ExecutionApprovalReview,
    InMemoryHumanApprovalAuthority,
    _execution_approval_authority_registered,
    _register_in_memory_execution_approval_authority,
    _register_studio_execution_approval_authority,
    _validate_approval_check_for_snapshot,
    _validate_authority_snapshot_for_review,
    _validate_prepared_review_for_review,
    _authority_functions,
)
from worldforge.agent_harness.capability_broker import CapabilityBroker
from worldforge.agent_harness.kernel import KernelError
from worldforge.agent_harness.ports import ProviderTurnResult, ToolResult
from worldforge.studio import authenticated_human_decisions as studio_authority_module
from worldforge.studio.authenticated_human_decisions import (
    StudioAuthenticatedHumanDecisionAuthority,
    _complete_studio_authority_registration,
    _consume_studio_authority_registration_provenance,
    _credential_evidence,
    _new_provisional_studio_authority,
)
from worldforge.studio.errors import StudioError
from worldforge.studio.storage import StudioStore


_PASSPHRASE = "director-test-passphrase"


class StudioAgentHarnessApprovalBridgeTests(unittest.TestCase):
    def _isolated_studio_capability(
        self,
        store: StudioStore,
        register,
    ):
        provisional, complete, consume = (
            studio_authority_module._build_studio_authority_construction_capsule(
                register
            )
        )
        entrypoint = vars(StudioAuthenticatedHumanDecisionAuthority)["unlock"]
        authority = entrypoint._implementation(
            StudioAuthenticatedHumanDecisionAuthority,
            store,
            provisional,
            complete,
            passphrase=_PASSPHRASE,
        )
        return authority, consume

    def _assert_authority_attack_has_no_execution_effects(self, authority: object) -> None:
        activation, grant = _documents(capabilities=["tool.invoke"], tools=["source.read"])
        request = replace(_request(activation, grant), approval_id="approval_execution_01")
        provider = FakeProvider([ProviderTurnResult("done", _usage(), completed=True)])
        tool = FakeTool("source.read", "tool.invoke", ToolResult("unused"))
        journal = FakeJournal()
        try:
            kernel = _ProviderAutoApprovingKernel(
                provider=provider,
                broker=CapabilityBroker(tools=(tool,)),
                journal=journal,
                clock=FakeClock(),
                cancellation=FakeCancellation(),
                approval_authority=authority,
            )
        except KernelError as exc:
            self.assertEqual("approval_authority_invalid", exc.reason_code)
            self.assertEqual([], journal.begin_calls)
            self.assertEqual([], provider.requests)
            self.assertEqual([], tool.calls)
            return

        review = kernel.prepare_approval_review(request)
        decision = ExecutionApprovalDecision.create(
            review=review,
            reviewer_id=(
                "director_local"
                if type(authority) is StudioAuthenticatedHumanDecisionAuthority
                else "attacker_local"
            ),
            outcome="approved",
            approved_tool_ids=("source.read",),
            expires_at_ms=2_000,
        )
        authority.decide(
            decision,
            expected_generation=0,
            expected_review_hash=review.content_hash,
        )
        kernel.execute(request)
        self.fail(
            "mutable trust seam reached effects: "
            f"journal={len(journal.begin_calls)} provider={len(provider.requests)} "
            f"tool={len(tool.calls)}"
        )

    def test_mutable_in_memory_admission_constants_cannot_register_exact_forgery(
        self,
    ) -> None:
        forged = object.__new__(InMemoryHumanApprovalAuthority)
        forged._records = {}
        forged._lock = threading.RLock()
        original_code = approvals_module._IN_MEMORY_AUTHORITY_CONSTRUCTOR_CODE
        original_functions = approvals_module._IN_MEMORY_AUTHORITY_FUNCTIONS
        approvals_module._IN_MEMORY_AUTHORITY_CONSTRUCTOR_CODE = sys._getframe().f_code
        approvals_module._IN_MEMORY_AUTHORITY_FUNCTIONS = _authority_functions(
            InMemoryHumanApprovalAuthority
        )
        try:
            _register_in_memory_execution_approval_authority(forged)
        except ApprovalError as exc:
            self.assertEqual("approval_authority_invalid", exc.reason_code)
            return
        finally:
            approvals_module._IN_MEMORY_AUTHORITY_CONSTRUCTOR_CODE = original_code
            approvals_module._IN_MEMORY_AUTHORITY_FUNCTIONS = original_functions
        self._assert_authority_attack_has_no_execution_effects(forged)

    def test_mutable_function_derivation_cannot_admit_replaced_exact_class_methods(
        self,
    ) -> None:
        original_prepare = InMemoryHumanApprovalAuthority.prepare
        original_functions = approvals_module._IN_MEMORY_AUTHORITY_FUNCTIONS
        original_derivation = approvals_module._authority_functions

        def forged_prepare(self, review: object, *, expected_generation: object):
            return original_prepare(
                self,
                review,
                expected_generation=expected_generation,
            )

        InMemoryHumanApprovalAuthority.prepare = forged_prepare
        forged_functions = (
            ("prepare", forged_prepare, forged_prepare.__code__),
            *original_functions[1:],
        )
        approvals_module._IN_MEMORY_AUTHORITY_FUNCTIONS = forged_functions
        approvals_module._authority_functions = lambda _authority_type: forged_functions
        try:
            try:
                forged = InMemoryHumanApprovalAuthority()
            except ApprovalError as exc:
                self.assertEqual("approval_authority_invalid", exc.reason_code)
                return
            self._assert_authority_attack_has_no_execution_effects(forged)
        finally:
            approvals_module._authority_functions = original_derivation
            approvals_module._IN_MEMORY_AUTHORITY_FUNCTIONS = original_functions
            InMemoryHumanApprovalAuthority.prepare = original_prepare

    def test_mutable_studio_provenance_consumer_cannot_register_a_copy(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = StudioStore(Path(temporary) / "studio")
            try:
                authority = StudioAuthenticatedHumanDecisionAuthority.enroll(
                    store, passphrase=_PASSPHRASE
                )
                forged = copy(authority)
                original_consume = (
                    studio_authority_module._consume_studio_authority_registration_provenance
                )
                studio_authority_module._consume_studio_authority_registration_provenance = (
                    lambda value, _token: tuple(
                        (name, object.__getattribute__(value, name))
                        for name in (
                            "_store",
                            "_event_key",
                            "_credential",
                            "_connection",
                            "_lock",
                        )
                    )
                )
                try:
                    _register_studio_execution_approval_authority(forged, object())
                except ApprovalError as exc:
                    self.assertEqual("approval_authority_invalid", exc.reason_code)
                    return
                finally:
                    studio_authority_module._consume_studio_authority_registration_provenance = (
                        original_consume
                    )
                self._assert_authority_attack_has_no_execution_effects(forged)
            finally:
                store.close()

    def test_mutable_registry_validator_cannot_admit_an_unregistered_copy(self) -> None:
        original = InMemoryHumanApprovalAuthority()
        forged = copy(original)
        original_validate = approvals_module._validate_registered_execution_approval_authority
        approvals_module._validate_registered_execution_approval_authority = (
            lambda _value: _authority_functions(InMemoryHumanApprovalAuthority)
        )
        try:
            self._assert_authority_attack_has_no_execution_effects(forged)
        finally:
            approvals_module._validate_registered_execution_approval_authority = (
                original_validate
            )

    def test_mutable_binding_validator_cannot_restore_revoked_state_owner(self) -> None:
        activation, grant = _documents(capabilities=["tool.invoke"], tools=["source.read"])
        request = replace(_request(activation, grant), approval_id="approval_execution_01")
        authority = InMemoryHumanApprovalAuthority()
        provider = FakeProvider([ProviderTurnResult("done", _usage(), completed=True)])
        journal = FakeJournal()
        kernel = _ProviderAutoApprovingKernel(
            provider=provider,
            broker=CapabilityBroker(
                tools=(FakeTool("source.read", "tool.invoke", ToolResult("unused")),)
            ),
            journal=journal,
            clock=FakeClock(),
            cancellation=FakeCancellation(),
            approval_authority=authority,
        )
        review = kernel.prepare_approval_review(request)
        decision = ExecutionApprovalDecision.create(
            review=review,
            reviewer_id="reviewer_local_01",
            outcome="approved",
            approved_tool_ids=("source.read",),
            expires_at_ms=2_000,
        )
        authority.decide(
            decision,
            expected_generation=0,
            expected_review_hash=review.content_hash,
        )
        approved_records = deepcopy(authority._records)
        authority.revoke(
            review.approval_id,
            expected_generation=1,
            expected_decision_hash=decision.content_hash,
        )
        authority._records = approved_records
        original_validate = approvals_module._validate_registered_execution_approval_authority
        approvals_module._validate_registered_execution_approval_authority = lambda _value: ()
        try:
            with self.assertRaisesRegex(KernelError, "approval_authority_invalid"):
                kernel.execute(request)
        finally:
            approvals_module._validate_registered_execution_approval_authority = (
                original_validate
            )
        self.assertEqual([], journal.begin_calls)
        self.assertEqual([], provider.requests)

    def test_mutable_binding_validate_method_cannot_restore_revoked_state_owner(self) -> None:
        activation, grant = _documents(capabilities=["tool.invoke"], tools=["source.read"])
        request = replace(_request(activation, grant), approval_id="approval_execution_01")
        authority = InMemoryHumanApprovalAuthority()
        provider = FakeProvider([ProviderTurnResult("done", _usage(), completed=True)])
        journal = FakeJournal()
        kernel = _ProviderAutoApprovingKernel(
            provider=provider,
            broker=CapabilityBroker(
                tools=(FakeTool("source.read", "tool.invoke", ToolResult("unused")),)
            ),
            journal=journal,
            clock=FakeClock(),
            cancellation=FakeCancellation(),
            approval_authority=authority,
        )
        review = kernel.prepare_approval_review(request)
        decision = ExecutionApprovalDecision.create(
            review=review,
            reviewer_id="reviewer_local_01",
            outcome="approved",
            approved_tool_ids=("source.read",),
            expires_at_ms=2_000,
        )
        authority.decide(
            decision,
            expected_generation=0,
            expected_review_hash=review.content_hash,
        )
        approved_records = deepcopy(authority._records)
        authority.revoke(
            review.approval_id,
            expected_generation=1,
            expected_decision_hash=decision.content_hash,
        )
        authority._records = approved_records
        binding_type = type(kernel._approval_authority)
        original_validate = binding_type.validate
        binding_type.validate = lambda _binding: None
        try:
            with self.assertRaisesRegex(KernelError, "approval_authority_invalid"):
                kernel.execute(request)
        finally:
            binding_type.validate = original_validate
        self.assertEqual([], journal.begin_calls)
        self.assertEqual([], provider.requests)

    def test_kernel_approval_validation_handle_cannot_be_reassigned(self) -> None:
        activation, grant = _documents(capabilities=["tool.invoke"], tools=["source.read"])
        request = replace(_request(activation, grant), approval_id="approval_execution_01")
        authority = InMemoryHumanApprovalAuthority()
        provider = FakeProvider([ProviderTurnResult("done", _usage(), completed=True)])
        tool = FakeTool("source.read", "tool.invoke", ToolResult("unused"))
        journal = FakeJournal()
        kernel = _ProviderAutoApprovingKernel(
            provider=provider,
            broker=CapabilityBroker(tools=(tool,)),
            journal=journal,
            clock=FakeClock(),
            cancellation=FakeCancellation(),
            approval_authority=authority,
        )
        review = kernel.prepare_approval_review(request)
        decision = ExecutionApprovalDecision.create(
            review=review,
            reviewer_id="reviewer_local_01",
            outcome="approved",
            approved_tool_ids=("source.read",),
            expires_at_ms=2_000,
        )
        authority.decide(
            decision,
            expected_generation=0,
            expected_review_hash=review.content_hash,
        )
        approved_records = deepcopy(authority._records)
        self.assertIsNot(
            approved_records[review.approval_id],
            authority._records[review.approval_id],
        )
        authority.revoke(
            review.approval_id,
            expected_generation=1,
            expected_decision_hash=decision.content_hash,
        )
        authority._records = approved_records
        with self.assertRaisesRegex(AttributeError, "capsule-owned"):
            kernel._approval_authority_validate = lambda: None

        with self.assertRaisesRegex(KernelError, "approval_authority_invalid"):
            kernel.execute(request)
        self.assertEqual([], journal.begin_calls)
        self.assertEqual([], provider.requests)
        self.assertEqual([], tool.calls)

    def test_replaced_binder_alias_before_kernel_construction_cannot_admit_copy(
        self,
    ) -> None:
        original = InMemoryHumanApprovalAuthority()
        forged = copy(original)

        class ForgedBinding:
            def __init__(self) -> None:
                self.owner = forged
                self.prepare = forged.prepare
                self.snapshot = forged.snapshot
                self.check_snapshot = forged.check_snapshot

            def validate(self) -> None:
                return None

        original_binder = kernel_module._validate_execution_approval_authority
        kernel_module._validate_execution_approval_authority = lambda _value: ForgedBinding()
        try:
            self._assert_authority_attack_has_no_execution_effects(forged)
        finally:
            kernel_module._validate_execution_approval_authority = original_binder

    def test_execution_authority_capsule_captures_registration_primitives(self) -> None:
        original_sys = approvals_module.sys
        original_ref = approvals_module.ref
        original_type = getattr(approvals_module, "type", None)
        original_id = getattr(approvals_module, "id", None)

        def forbidden(*_args: object, **_kwargs: object):
            raise AssertionError("mutable module primitive was consulted")

        replacements = (
            ("sys", forbidden),
            ("ref", forbidden),
            ("type", forbidden),
            ("id", forbidden),
        )
        try:
            for name, replacement in replacements:
                with self.subTest(name=name):
                    setattr(approvals_module, name, replacement)
                    try:
                        authority = InMemoryHumanApprovalAuthority()
                        self.assertTrue(_execution_approval_authority_registered(authority))
                    finally:
                        if name == "sys":
                            approvals_module.sys = original_sys
                        elif name == "ref":
                            approvals_module.ref = original_ref
                        elif name == "type":
                            delattr(approvals_module, "type")
                        else:
                            delattr(approvals_module, "id")
        finally:
            approvals_module.sys = original_sys
            approvals_module.ref = original_ref
            if original_type is None:
                if hasattr(approvals_module, "type"):
                    delattr(approvals_module, "type")
            else:
                approvals_module.type = original_type
            if original_id is None:
                if hasattr(approvals_module, "id"):
                    delattr(approvals_module, "id")
            else:
                approvals_module.id = original_id

    def test_execution_authority_capsule_captures_binding_primitives(self) -> None:
        mutable_names = (
            "object",
            "type",
            "id",
            "all",
            "any",
            "vars",
            "FunctionType",
            "MethodType",
            "_ExecutionApprovalAuthorityBinding",
        )
        originals = {
            name: getattr(approvals_module, name, None) for name in mutable_names
        }

        def forbidden(*_args: object, **_kwargs: object):
            raise AssertionError("mutable module primitive was consulted")

        try:
            for name in mutable_names:
                with self.subTest(name=name):
                    authority = InMemoryHumanApprovalAuthority()
                    setattr(approvals_module, name, forbidden)
                    try:
                        kernel = _ProviderAutoApprovingKernel(
                            provider=FakeProvider([]),
                            broker=CapabilityBroker(),
                            journal=FakeJournal(),
                            clock=FakeClock(),
                            cancellation=FakeCancellation(),
                            approval_authority=authority,
                        )
                        self.assertIs(authority, kernel._approval_authority.owner)
                    finally:
                        if originals[name] is None:
                            delattr(approvals_module, name)
                        else:
                            setattr(approvals_module, name, originals[name])
        finally:
            for name, value in originals.items():
                if value is None:
                    if hasattr(approvals_module, name):
                        delattr(approvals_module, name)
                else:
                    setattr(approvals_module, name, value)

    def test_mutable_frame_accessor_cannot_register_forged_in_memory_authority(
        self,
    ) -> None:
        forged = object.__new__(InMemoryHumanApprovalAuthority)
        forged._records = {}
        forged._lock = threading.RLock()
        original_sys = approvals_module.sys

        class ForgedFrame:
            f_code = InMemoryHumanApprovalAuthority.__init__.__code__

        class ForgedSys:
            @staticmethod
            def _getframe(_depth: int):
                return ForgedFrame()

        approvals_module.sys = ForgedSys()
        try:
            with self.assertRaisesRegex(ApprovalError, "approval_authority_invalid"):
                _register_in_memory_execution_approval_authority(forged)
        finally:
            approvals_module.sys = original_sys
        self.assertFalse(_execution_approval_authority_registered(forged))

    def test_mutable_studio_frame_accessor_cannot_complete_copied_authority(
        self,
    ) -> None:
        original_sys = studio_authority_module.sys
        entrypoint = vars(StudioAuthenticatedHumanDecisionAuthority)["unlock"]

        class ForgedFrame:
            f_code = entrypoint._implementation.__code__

        class ForgedSys:
            @staticmethod
            def _getframe(_depth: int):
                return ForgedFrame()

        with tempfile.TemporaryDirectory() as temporary:
            store = StudioStore(Path(temporary) / "studio")
            try:
                authority = StudioAuthenticatedHumanDecisionAuthority.enroll(
                    store, passphrase=_PASSPHRASE
                )
                forged = copy(authority)
                studio_authority_module.sys = ForgedSys()
                try:
                    with self.assertRaisesRegex(
                        ApprovalError, "approval_authority_invalid"
                    ):
                        _complete_studio_authority_registration(
                            forged,
                            store,
                            forged._event_key,
                            forged._credential,
                        )
                finally:
                    studio_authority_module.sys = original_sys
                self.assertFalse(_execution_approval_authority_registered(forged))
                self._assert_authority_attack_has_no_execution_effects(forged)
            finally:
                studio_authority_module.sys = original_sys
                store.close()

    def test_mutable_studio_frame_accessor_cannot_create_provisional_authority(
        self,
    ) -> None:
        original_sys = studio_authority_module.sys
        entrypoint = vars(StudioAuthenticatedHumanDecisionAuthority)["enroll"]
        returned: list[object] = []

        class ForgedFrame:
            f_code = entrypoint._implementation.__code__

        class ForgedSys:
            @staticmethod
            def _getframe(_depth: int):
                return ForgedFrame()

        with tempfile.TemporaryDirectory() as temporary:
            store = StudioStore(Path(temporary) / "studio")
            try:
                authority = StudioAuthenticatedHumanDecisionAuthority.enroll(
                    store, passphrase=_PASSPHRASE
                )
                studio_authority_module.sys = ForgedSys()
                try:
                    with self.assertRaisesRegex(
                        ApprovalError, "approval_authority_invalid"
                    ):
                        returned.append(
                            _new_provisional_studio_authority(
                                StudioAuthenticatedHumanDecisionAuthority,
                                store,
                                authority._event_key,
                                authority._credential,
                            )
                        )
                finally:
                    studio_authority_module.sys = original_sys
                self.assertEqual([], returned)
            finally:
                studio_authority_module.sys = original_sys
                store.close()

    def test_mutable_studio_bound_entrypoint_factory_cannot_return_copy(self) -> None:
        original_factory = studio_authority_module._BoundStudioConstructionEntrypoint
        substituted: list[object] = []
        original_authority: object | None = None

        def forged_factory(_owner, _implementation, _provisional, _complete):
            def forged_unlock(store: StudioStore, *, passphrase: object):
                del store
                del passphrase
                forged = copy(original_authority)
                substituted.append(forged)
                return forged

            return forged_unlock

        with tempfile.TemporaryDirectory() as temporary:
            store = StudioStore(Path(temporary) / "studio")
            try:
                original_authority = StudioAuthenticatedHumanDecisionAuthority.enroll(
                    store, passphrase=_PASSPHRASE
                )
                studio_authority_module._BoundStudioConstructionEntrypoint = forged_factory
                try:
                    authority = StudioAuthenticatedHumanDecisionAuthority.unlock(
                        store, passphrase=_PASSPHRASE
                    )
                finally:
                    studio_authority_module._BoundStudioConstructionEntrypoint = (
                        original_factory
                    )
                self.assertEqual([], substituted)
                self.assertTrue(_execution_approval_authority_registered(authority))
            finally:
                studio_authority_module._BoundStudioConstructionEntrypoint = original_factory
                store.close()

    def test_studio_construction_capsule_captures_identity_and_token_factory(
        self,
    ) -> None:
        originals = {
            "id": getattr(studio_authority_module, "id", None),
            "object": getattr(studio_authority_module, "object", None),
        }

        def forbidden(*_args: object, **_kwargs: object):
            raise AssertionError("mutable Studio primitive was consulted")

        with tempfile.TemporaryDirectory() as temporary:
            studio_path = Path(temporary) / "studio"
            enrolled = StudioStore(studio_path)
            try:
                StudioAuthenticatedHumanDecisionAuthority.enroll(
                    enrolled, passphrase=_PASSPHRASE
                )
            finally:
                enrolled.close()

            for name in originals:
                with self.subTest(name=name):
                    store = StudioStore(studio_path)
                    setattr(studio_authority_module, name, forbidden)
                    try:
                        authority = StudioAuthenticatedHumanDecisionAuthority.unlock(
                            store, passphrase=_PASSPHRASE
                        )
                        self.assertTrue(
                            _execution_approval_authority_registered(authority)
                        )
                    finally:
                        if originals[name] is None:
                            delattr(studio_authority_module, name)
                        else:
                            setattr(studio_authority_module, name, originals[name])
                        store.close()

    def test_studio_capability_rejects_equal_nonidentical_construction_values(
        self,
    ) -> None:
        for field in ("_credential", "_event_key"):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary:
                studio_path = Path(temporary) / "studio"
                enrolled = StudioStore(studio_path)
                try:
                    StudioAuthenticatedHumanDecisionAuthority.enroll(
                        enrolled, passphrase=_PASSPHRASE
                    )
                finally:
                    enrolled.close()
                store = StudioStore(studio_path)
                captured: dict[str, object] = {}

                def capture(authority: object, token: object) -> None:
                    captured["authority"] = authority
                    captured["token"] = token

                try:
                    authority, consume = self._isolated_studio_capability(store, capture)
                    token = captured["token"]
                    if field == "_credential":
                        original = authority._credential
                        replacement = replace(original)
                    else:
                        original = authority._event_key
                        replacement = bytes(bytearray(original))
                    self.assertEqual(original, replacement)
                    self.assertIsNot(original, replacement)
                    setattr(authority, field, replacement)
                    with self.assertRaisesRegex(
                        ApprovalError, "approval_authority_invalid"
                    ):
                        consume(authority, token)
                    self.assertFalse(_execution_approval_authority_registered(authority))
                finally:
                    store.close()

    def test_studio_capability_is_one_shot_and_retires_after_registration_failure(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            studio_path = Path(temporary) / "studio"
            enrolled = StudioStore(studio_path)
            try:
                StudioAuthenticatedHumanDecisionAuthority.enroll(
                    enrolled, passphrase=_PASSPHRASE
                )
            finally:
                enrolled.close()

            store = StudioStore(studio_path)
            captured: dict[str, object] = {}

            def capture(authority: object, token: object) -> None:
                captured["authority"] = authority
                captured["token"] = token

            try:
                authority, consume = self._isolated_studio_capability(store, capture)
                token = captured["token"]
                sealed = consume(authority, token)
                self.assertEqual(
                    ("_store", "_event_key", "_credential", "_connection", "_lock"),
                    tuple(name for name, _value in sealed),
                )
                with self.assertRaisesRegex(ApprovalError, "approval_authority_invalid"):
                    consume(authority, token)
            finally:
                store.close()

        with tempfile.TemporaryDirectory() as temporary:
            studio_path = Path(temporary) / "studio"
            enrolled = StudioStore(studio_path)
            try:
                StudioAuthenticatedHumanDecisionAuthority.enroll(
                    enrolled, passphrase=_PASSPHRASE
                )
            finally:
                enrolled.close()
            store = StudioStore(studio_path)
            captured = {}

            def reject(authority: object, token: object) -> None:
                captured["authority"] = authority
                captured["token"] = token
                raise ApprovalError("approval_authority_invalid")

            provisional, complete, consume = (
                studio_authority_module._build_studio_authority_construction_capsule(
                    reject
                )
            )
            entrypoint = vars(StudioAuthenticatedHumanDecisionAuthority)["unlock"]
            try:
                with self.assertRaisesRegex(
                    StudioError, "authenticated decision audit failed"
                ):
                    entrypoint._implementation(
                        StudioAuthenticatedHumanDecisionAuthority,
                        store,
                        provisional,
                        complete,
                        passphrase=_PASSPHRASE,
                    )
                with self.assertRaisesRegex(ApprovalError, "approval_authority_invalid"):
                    consume(captured["authority"], captured["token"])
                self.assertFalse(
                    _execution_approval_authority_registered(captured["authority"])
                )
            finally:
                store.close()

    def test_replaced_binding_validator_before_kernel_construction_is_rejected(
        self,
    ) -> None:
        authority = InMemoryHumanApprovalAuthority()
        binding_type = approvals_module._ExecutionApprovalAuthorityBinding
        original_validate = binding_type.validate
        binding_type.validate = lambda _binding: None
        journal = FakeJournal()
        provider = FakeProvider([])
        try:
            with self.assertRaisesRegex(KernelError, "approval_authority_invalid"):
                _ProviderAutoApprovingKernel(
                    provider=provider,
                    broker=CapabilityBroker(),
                    journal=journal,
                    clock=FakeClock(),
                    cancellation=FakeCancellation(),
                    approval_authority=authority,
                )
        finally:
            binding_type.validate = original_validate
        self.assertEqual([], journal.begin_calls)
        self.assertEqual([], provider.requests)

    def test_mutable_studio_registration_completion_cannot_return_unregistered_authority(
        self,
    ) -> None:
        captured: dict[str, object] = {}

        def bypass_registration(authority: object, token: object) -> None:
            captured["authority"] = authority
            captured["token"] = token

        with tempfile.TemporaryDirectory() as temporary:
            store = StudioStore(Path(temporary) / "studio")
            original_register = (
                studio_authority_module._register_studio_execution_approval_authority
            )
            studio_authority_module._register_studio_execution_approval_authority = (
                bypass_registration
            )
            try:
                authority = StudioAuthenticatedHumanDecisionAuthority.enroll(
                    store, passphrase=_PASSPHRASE
                )
            finally:
                studio_authority_module._register_studio_execution_approval_authority = (
                    original_register
                )
            try:
                self.assertTrue(_execution_approval_authority_registered(authority))
                self.assertEqual({}, captured)
            finally:
                store.close()

    def test_mutable_studio_completion_dispatch_cannot_return_unregistered_authority(
        self,
    ) -> None:
        called = 0

        def bypass_completion(*_args: object) -> None:
            nonlocal called
            called += 1

        with tempfile.TemporaryDirectory() as temporary:
            store = StudioStore(Path(temporary) / "studio")
            original_complete = (
                studio_authority_module._complete_studio_authority_registration
            )
            studio_authority_module._complete_studio_authority_registration = (
                bypass_completion
            )
            try:
                authority = StudioAuthenticatedHumanDecisionAuthority.enroll(
                    store, passphrase=_PASSPHRASE
                )
            finally:
                studio_authority_module._complete_studio_authority_registration = (
                    original_complete
                )
            try:
                self.assertEqual(0, called)
                self.assertTrue(_execution_approval_authority_registered(authority))
            finally:
                store.close()

    def test_mutable_studio_provisional_dispatch_cannot_substitute_a_copy(self) -> None:
        called = 0
        original_provisional = studio_authority_module._new_provisional_studio_authority

        def substitute_copy(
            authority_type: object,
            store: StudioStore,
            event_key: bytes,
            credential: object,
        ):
            nonlocal called
            called += 1
            authority = object.__new__(authority_type)
            authority._store = store
            authority._event_key = event_key
            authority._credential = credential
            authority._anchor = studio_authority_module._EMPTY_AUDIT_HEAD
            authority._poisoned = False
            authority._connection = store._authenticated_human_decision_connection()
            authority._lock = store._authenticated_human_decision_lock
            return authority

        with tempfile.TemporaryDirectory() as temporary:
            store = StudioStore(Path(temporary) / "studio")
            studio_authority_module._new_provisional_studio_authority = substitute_copy
            try:
                authority = StudioAuthenticatedHumanDecisionAuthority.enroll(
                    store, passphrase=_PASSPHRASE
                )
            finally:
                studio_authority_module._new_provisional_studio_authority = (
                    original_provisional
                )
            try:
                self.assertEqual(0, called)
                self.assertTrue(_execution_approval_authority_registered(authority))
            finally:
                store.close()

    def test_direct_studio_constructor_cannot_seed_approval_chain_without_passphrase(
        self,
    ) -> None:
        activation, grant = _documents(capabilities=["tool.invoke"], tools=["source.read"])
        request = replace(_request(activation, grant), approval_id="approval_execution_01")
        provider = FakeProvider([ProviderTurnResult("done", _usage(), completed=True)])
        journal = FakeJournal()
        with tempfile.TemporaryDirectory() as temporary:
            store = StudioStore(Path(temporary) / "studio")
            try:
                StudioAuthenticatedHumanDecisionAuthority.enroll(
                    store, passphrase=_PASSPHRASE
                )
                row = store.connection.execute(
                    "SELECT credential_id, kdf_name, kdf_n, kdf_r, kdf_p, kdf_dklen, "
                    "kdf_maxmem, salt, verifier, created_at FROM "
                    "studio_authenticated_human_credentials"
                ).fetchone()
                credential = _credential_evidence(row)
                try:
                    forged = StudioAuthenticatedHumanDecisionAuthority(
                        store,
                        b"x" * 32,
                        credential,
                    )
                except ApprovalError as exc:
                    self.assertEqual("approval_authority_invalid", exc.reason_code)
                    self.assertEqual([], journal.begin_calls)
                    self.assertEqual([], provider.requests)
                    return

                kernel = _ProviderAutoApprovingKernel(
                    provider=provider,
                    broker=CapabilityBroker(
                        tools=(
                            FakeTool("source.read", "tool.invoke", ToolResult("unused")),
                        )
                    ),
                    journal=journal,
                    clock=FakeClock(),
                    cancellation=FakeCancellation(),
                    approval_authority=forged,
                )
                review = kernel.prepare_approval_review(request)
                decision = ExecutionApprovalDecision.create(
                    review=review,
                    reviewer_id="director_local",
                    outcome="approved",
                    approved_tool_ids=("source.read",),
                    expires_at_ms=2_000,
                )
                forged.decide(
                    decision,
                    expected_generation=0,
                    expected_review_hash=review.content_hash,
                )
                kernel.execute(request)
                self.fail(
                    "direct Studio construction reached effects: "
                    f"journal={len(journal.begin_calls)} provider={len(provider.requests)}"
                )
            finally:
                store.close()

    def test_studio_construction_provenance_cannot_be_guessed_reused_or_rebound(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = StudioStore(Path(temporary) / "studio")
            other_store = StudioStore(Path(temporary) / "other")
            try:
                authority = StudioAuthenticatedHumanDecisionAuthority.enroll(
                    store, passphrase=_PASSPHRASE
                )
                self.assertNotIn("provenance", vars(authority))
                self.assertNotIn("token", vars(authority))
                row = store.connection.execute(
                    "SELECT credential_id, kdf_name, kdf_n, kdf_r, kdf_p, kdf_dklen, "
                    "kdf_maxmem, salt, verifier, created_at FROM "
                    "studio_authenticated_human_credentials"
                ).fetchone()
                credential = _credential_evidence(row)
                with self.assertRaisesRegex(ApprovalError, "approval_authority_invalid"):
                    StudioAuthenticatedHumanDecisionAuthority(
                        store,
                        authority._event_key,
                        credential,
                        provenance=object(),
                    )
                with self.assertRaisesRegex(ApprovalError, "approval_authority_invalid"):
                    _register_studio_execution_approval_authority(authority, object())
                with self.assertRaisesRegex(ApprovalError, "approval_authority_invalid"):
                    _new_provisional_studio_authority(
                        StudioAuthenticatedHumanDecisionAuthority,
                        store,
                        authority._event_key,
                        credential,
                    )
                for candidate_store, candidate_key in (
                    (store, authority._event_key),
                    (other_store, authority._event_key),
                    (store, b"z" * 32),
                ):
                    with self.subTest(store=candidate_store, key=candidate_key):
                        with self.assertRaisesRegex(
                            ApprovalError, "approval_authority_invalid"
                        ):
                            _complete_studio_authority_registration(
                                authority,
                                candidate_store,
                                candidate_key,
                                credential,
                            )
            finally:
                other_store.close()
                store.close()

    def test_studio_construction_capability_binds_exact_construction_objects(
        self,
    ) -> None:
        captured: dict[str, object] = {}

        def capture(authority: object, token: object) -> None:
            captured["authority"] = authority
            captured["token"] = token

        with tempfile.TemporaryDirectory() as temporary:
            store = StudioStore(Path(temporary) / "studio")
            try:
                StudioAuthenticatedHumanDecisionAuthority.enroll(
                    store, passphrase=_PASSPHRASE
                )
                original_register = (
                    studio_authority_module._register_studio_execution_approval_authority
                )

                studio_authority_module._register_studio_execution_approval_authority = (
                    capture
                )
                try:
                    authority = StudioAuthenticatedHumanDecisionAuthority.unlock(
                        store, passphrase=_PASSPHRASE
                    )
                finally:
                    studio_authority_module._register_studio_execution_approval_authority = (
                        original_register
                    )
                self.assertEqual({}, captured)
                self.assertTrue(_execution_approval_authority_registered(authority))
            finally:
                store.close()

    def test_failed_studio_registration_discards_issued_capability(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            studio_path = Path(temporary) / "studio"
            store = StudioStore(studio_path)
            try:
                StudioAuthenticatedHumanDecisionAuthority.enroll(
                    store, passphrase=_PASSPHRASE
                )
            finally:
                store.close()

            store = StudioStore(studio_path)
            original_prepare = StudioAuthenticatedHumanDecisionAuthority.prepare
            returned: list[object] = []
            StudioAuthenticatedHumanDecisionAuthority.prepare = lambda self, review, **kwargs: (
                review
            )
            try:
                try:
                    with self.assertRaisesRegex(
                        StudioError, "authenticated decision audit failed"
                    ):
                        returned.append(
                            StudioAuthenticatedHumanDecisionAuthority.unlock(
                                store, passphrase=_PASSPHRASE
                            )
                        )
                finally:
                    StudioAuthenticatedHumanDecisionAuthority.prepare = original_prepare
            finally:
                store.close()
            self.assertEqual([], returned)

            store = StudioStore(studio_path)
            try:
                authority = StudioAuthenticatedHumanDecisionAuthority.unlock(
                    store, passphrase=_PASSPHRASE
                )
                self.assertTrue(_execution_approval_authority_registered(authority))
            finally:
                store.close()

    def test_studio_registration_uses_captured_provenance_consumer(
        self,
    ) -> None:
        called = 0

        def replace_consumer(_authority: object, _token: object):
            nonlocal called
            called += 1
            return ()

        with tempfile.TemporaryDirectory() as temporary:
            store = StudioStore(Path(temporary) / "studio")
            original_consume = (
                studio_authority_module._consume_studio_authority_registration_provenance
            )
            studio_authority_module._consume_studio_authority_registration_provenance = (
                replace_consumer
            )
            try:
                authority = StudioAuthenticatedHumanDecisionAuthority.enroll(
                    store, passphrase=_PASSPHRASE
                )
            finally:
                studio_authority_module._consume_studio_authority_registration_provenance = (
                    original_consume
                )
            try:
                self.assertEqual(0, called)
                self.assertTrue(_execution_approval_authority_registered(authority))
            finally:
                store.close()

    def test_registered_studio_construction_state_cannot_be_rebound(self) -> None:
        activation, grant = _documents(capabilities=["tool.invoke"], tools=["source.read"])
        request = replace(_request(activation, grant), approval_id="approval_execution_01")
        provider = FakeProvider([ProviderTurnResult("done", _usage(), completed=True)])
        journal = FakeJournal()
        with tempfile.TemporaryDirectory() as temporary:
            store = StudioStore(Path(temporary) / "studio")
            try:
                authority = StudioAuthenticatedHumanDecisionAuthority.enroll(
                    store, passphrase=_PASSPHRASE
                )
                authority._event_key = b"x" * 32
                try:
                    kernel = _ProviderAutoApprovingKernel(
                        provider=provider,
                        broker=CapabilityBroker(
                            tools=(
                                FakeTool(
                                    "source.read",
                                    "tool.invoke",
                                    ToolResult("unused"),
                                ),
                            )
                        ),
                        journal=journal,
                        clock=FakeClock(),
                        cancellation=FakeCancellation(),
                        approval_authority=authority,
                    )
                except KernelError as exc:
                    self.assertEqual("approval_authority_invalid", exc.reason_code)
                    self.assertEqual([], journal.begin_calls)
                    self.assertEqual([], provider.requests)
                    return

                review = kernel.prepare_approval_review(request)
                decision = ExecutionApprovalDecision.create(
                    review=review,
                    reviewer_id="director_local",
                    outcome="approved",
                    approved_tool_ids=("source.read",),
                    expires_at_ms=2_000,
                )
                authority.decide(
                    decision,
                    expected_generation=0,
                    expected_review_hash=review.content_hash,
                )
                kernel.execute(request)
                self.fail(
                    "registered Studio construction rebind reached effects: "
                    f"journal={len(journal.begin_calls)} "
                    f"provider={len(provider.requests)}"
                )
            finally:
                store.close()

    def test_registered_authority_state_seals_reject_owner_and_store_swaps(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = StudioStore(Path(temporary) / "studio")
            other_store = StudioStore(Path(temporary) / "other")
            try:
                StudioAuthenticatedHumanDecisionAuthority.enroll(
                    store, passphrase=_PASSPHRASE
                )
                for field, replacement in (
                    ("_store", lambda _authority: other_store),
                    (
                        "_credential",
                        lambda authority: replace(authority._credential),
                    ),
                    (
                        "_connection",
                        lambda _authority: other_store._authenticated_human_decision_connection(),
                    ),
                    (
                        "_lock",
                        lambda _authority: other_store._authenticated_human_decision_lock,
                    ),
                ):
                    with self.subTest(authority="studio", field=field):
                        authority = StudioAuthenticatedHumanDecisionAuthority.unlock(
                            store, passphrase=_PASSPHRASE
                        )
                        setattr(authority, field, replacement(authority))
                        journal = FakeJournal()
                        provider = FakeProvider([])
                        with self.assertRaisesRegex(
                            KernelError, "approval_authority_invalid"
                        ):
                            _ProviderAutoApprovingKernel(
                                provider=provider,
                                broker=CapabilityBroker(),
                                journal=journal,
                                clock=FakeClock(),
                                cancellation=FakeCancellation(),
                                approval_authority=authority,
                            )
                        self.assertEqual([], journal.begin_calls)
                        self.assertEqual([], provider.requests)

                for field, replacement in (
                    ("_records", {}),
                    ("_lock", type(InMemoryHumanApprovalAuthority()._lock)()),
                ):
                    with self.subTest(authority="memory", field=field):
                        authority = InMemoryHumanApprovalAuthority()
                        setattr(authority, field, replacement)
                        journal = FakeJournal()
                        provider = FakeProvider([])
                        with self.assertRaisesRegex(
                            KernelError, "approval_authority_invalid"
                        ):
                            _ProviderAutoApprovingKernel(
                                provider=provider,
                                broker=CapabilityBroker(),
                                journal=journal,
                                clock=FakeClock(),
                                cancellation=FakeCancellation(),
                                approval_authority=authority,
                            )
                        self.assertEqual([], journal.begin_calls)
                        self.assertEqual([], provider.requests)
            finally:
                other_store.close()
                store.close()

    def test_authority_custody_rejects_copies_subclasses_uninitialized_and_registry_swap(
        self,
    ) -> None:
        original = InMemoryHumanApprovalAuthority()
        copied = copy(original)
        with self.assertRaisesRegex(ApprovalError, "approval_authority_invalid"):
            _register_in_memory_execution_approval_authority(copied)
        attacks: list[object] = [copied, object.__new__(InMemoryHumanApprovalAuthority)]
        try:
            attacks.append(deepcopy(original))
        except Exception:
            pass

        class DerivedAuthority(InMemoryHumanApprovalAuthority):
            pass

        with self.assertRaisesRegex(ApprovalError, "approval_authority_invalid"):
            DerivedAuthority()

        setattr(
            approvals_module,
            "_EXECUTION_APPROVAL_AUTHORITY_IDENTITIES",
            {id(copied): (ref(copied), type(copied), _authority_functions(type(copied)))},
        )
        try:
            for authority in attacks:
                with self.subTest(attack=type(authority).__name__):
                    journal = FakeJournal()
                    provider = FakeProvider([])
                    with self.assertRaisesRegex(
                        KernelError, "approval_authority_invalid"
                    ):
                        _ProviderAutoApprovingKernel(
                            provider=provider,
                            broker=CapabilityBroker(),
                            journal=journal,
                            clock=FakeClock(),
                            cancellation=FakeCancellation(),
                            approval_authority=authority,
                        )
                    self.assertEqual([], journal.begin_calls)
                    self.assertEqual([], provider.requests)
        finally:
            delattr(approvals_module, "_EXECUTION_APPROVAL_AUTHORITY_IDENTITIES")

    def test_method_shadow_after_kernel_construction_fails_before_effects(self) -> None:
        activation, grant = _documents(capabilities=["tool.invoke"], tools=["source.read"])
        request = replace(_request(activation, grant), approval_id="approval_execution_01")
        authority = InMemoryHumanApprovalAuthority()
        provider = FakeProvider([ProviderTurnResult("must not run", _usage(), completed=True)])
        tool = FakeTool("source.read", "tool.invoke", ToolResult("unused"))
        journal = FakeJournal()
        kernel = _ProviderAutoApprovingKernel(
            provider=provider,
            broker=CapabilityBroker(tools=(tool,)),
            journal=journal,
            clock=FakeClock(),
            cancellation=FakeCancellation(),
            approval_authority=authority,
        )
        review = kernel.prepare_approval_review(request)
        decision = ExecutionApprovalDecision.create(
            review=review,
            reviewer_id="reviewer_local_01",
            outcome="approved",
            approved_tool_ids=("source.read",),
            expires_at_ms=2_000,
        )
        authority.decide(
            decision,
            expected_generation=0,
            expected_review_hash=review.content_hash,
        )
        def shadow_snapshot(_review):
            return None

        setattr(authority, "snapshot", shadow_snapshot)

        with self.assertRaisesRegex(KernelError, "approval_authority_invalid"):
            kernel.execute(request)
        self.assertEqual([], journal.begin_calls)
        self.assertEqual([], provider.requests)
        self.assertEqual([], tool.calls)

    def test_class_method_replacement_after_construction_fails_before_effects(self) -> None:
        activation, grant = _documents(capabilities=["tool.invoke"], tools=["source.read"])
        request = replace(_request(activation, grant), approval_id="approval_execution_01")
        authority = InMemoryHumanApprovalAuthority()
        provider = FakeProvider([ProviderTurnResult("must not run", _usage(), completed=True)])
        journal = FakeJournal()
        kernel = _ProviderAutoApprovingKernel(
            provider=provider,
            broker=CapabilityBroker(
                tools=(FakeTool("source.read", "tool.invoke", ToolResult("unused")),)
            ),
            journal=journal,
            clock=FakeClock(),
            cancellation=FakeCancellation(),
            approval_authority=authority,
        )
        original_snapshot = InMemoryHumanApprovalAuthority.snapshot
        def replacement_snapshot(self, review):
            return None

        setattr(InMemoryHumanApprovalAuthority, "snapshot", replacement_snapshot)
        try:
            with self.assertRaisesRegex(KernelError, "approval_authority_invalid"):
                kernel.execute(request)
        finally:
            setattr(InMemoryHumanApprovalAuthority, "snapshot", original_snapshot)
        self.assertEqual([], journal.begin_calls)
        self.assertEqual([], provider.requests)

    def test_studio_snapshot_helpers_replaced_after_construction_fail_before_effects(
        self,
    ) -> None:
        activation, grant = _documents(capabilities=["tool.invoke"], tools=["source.read"])
        request = replace(_request(activation, grant), approval_id="approval_execution_01")

        for helper_name in ("_snapshot_in_transaction", "_row"):
            for replacement_scope in ("instance", "class"):
                with self.subTest(helper=helper_name, scope=replacement_scope):
                    with tempfile.TemporaryDirectory() as temporary:
                        store = StudioStore(Path(temporary) / "studio")
                        try:
                            authority = StudioAuthenticatedHumanDecisionAuthority.enroll(
                                store, passphrase=_PASSPHRASE
                            )
                            provider = FakeProvider(
                                [ProviderTurnResult("must not run", _usage(), completed=True)]
                            )
                            tool = FakeTool(
                                "source.read", "tool.invoke", ToolResult("unused")
                            )
                            journal = FakeJournal()
                            kernel = _ProviderAutoApprovingKernel(
                                provider=provider,
                                broker=CapabilityBroker(tools=(tool,)),
                                journal=journal,
                                clock=FakeClock(),
                                cancellation=FakeCancellation(),
                                approval_authority=authority,
                            )
                            review = kernel.prepare_approval_review(request)
                            decision = ExecutionApprovalDecision.create(
                                review=review,
                                reviewer_id="director_local",
                                outcome="approved",
                                approved_tool_ids=("source.read",),
                                expires_at_ms=2_000,
                            )
                            authority.decide(
                                decision,
                                expected_generation=0,
                                expected_review_hash=review.content_hash,
                            )

                            helper_calls: list[object] = []
                            original = getattr(
                                StudioAuthenticatedHumanDecisionAuthority, helper_name
                            )

                            if replacement_scope == "instance":

                                def replacement(*args, **kwargs):
                                    helper_calls.append(args)
                                    return original(authority, *args, **kwargs)

                                setattr(authority, helper_name, replacement)
                            else:

                                def replacement(owner, *args, **kwargs):
                                    helper_calls.append(args)
                                    return original(owner, *args, **kwargs)

                                setattr(
                                    StudioAuthenticatedHumanDecisionAuthority,
                                    helper_name,
                                    replacement,
                                )
                            try:
                                with self.assertRaisesRegex(
                                    KernelError, "approval_authority_invalid"
                                ):
                                    kernel.execute(request)
                            finally:
                                if replacement_scope == "class":
                                    setattr(
                                        StudioAuthenticatedHumanDecisionAuthority,
                                        helper_name,
                                        original,
                                    )

                            self.assertEqual([], helper_calls)
                            self.assertEqual([], journal.begin_calls)
                            self.assertEqual([], provider.requests)
                            self.assertEqual([], tool.calls)
                        finally:
                            store.close()

    def test_class_method_replacement_before_construction_cannot_be_registered(self) -> None:
        original_snapshot = InMemoryHumanApprovalAuthority.snapshot

        def replacement_snapshot(self, review):
            return None

        setattr(InMemoryHumanApprovalAuthority, "snapshot", replacement_snapshot)
        try:
            with self.assertRaisesRegex(ApprovalError, "approval_authority_invalid"):
                InMemoryHumanApprovalAuthority()
        finally:
            setattr(InMemoryHumanApprovalAuthority, "snapshot", original_snapshot)

    def test_constructor_replacement_cannot_register_forged_in_memory_authority(
        self,
    ) -> None:
        seed = InMemoryHumanApprovalAuthority()
        original_init = InMemoryHumanApprovalAuthority.__init__

        def replacement_init(authority):
            authority._records = {}
            authority._lock = seed._lock
            _register_in_memory_execution_approval_authority(authority)

        setattr(InMemoryHumanApprovalAuthority, "__init__", replacement_init)
        try:
            with self.assertRaisesRegex(ApprovalError, "approval_authority_invalid"):
                InMemoryHumanApprovalAuthority()
        finally:
            setattr(InMemoryHumanApprovalAuthority, "__init__", original_init)

    def test_authority_identity_registration_is_weak(self) -> None:
        authority = InMemoryHumanApprovalAuthority()
        authority_ref = ref(authority)
        self.assertTrue(_execution_approval_authority_registered(authority))

        del authority
        gc.collect()

        self.assertIsNone(authority_ref())
        replacement = object.__new__(InMemoryHumanApprovalAuthority)
        self.assertFalse(_execution_approval_authority_registered(replacement))

    def test_studio_authority_copy_is_rejected_before_effects(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = StudioStore(Path(temporary) / "studio")
            try:
                authority = StudioAuthenticatedHumanDecisionAuthority.enroll(
                    store, passphrase=_PASSPHRASE
                )
                copied = copy(authority)
                journal = FakeJournal()
                provider = FakeProvider([])
                with self.assertRaisesRegex(KernelError, "approval_authority_invalid"):
                    _ProviderAutoApprovingKernel(
                        provider=provider,
                        broker=CapabilityBroker(),
                        journal=journal,
                        clock=FakeClock(),
                        cancellation=FakeCancellation(),
                        approval_authority=copied,
                    )
                self.assertEqual([], journal.begin_calls)
                self.assertEqual([], provider.requests)
            finally:
                store.close()

    def test_method_swap_between_precheck_and_postcheck_stops_before_provider(self) -> None:
        activation, grant = _documents(capabilities=["tool.invoke"], tools=["source.read"])
        request = replace(_request(activation, grant), approval_id="approval_execution_01")
        authority = InMemoryHumanApprovalAuthority()
        provider = FakeProvider([ProviderTurnResult("must not run", _usage(), completed=True)])
        tool = FakeTool("source.read", "tool.invoke", ToolResult("unused"))

        class SwappingJournal(FakeJournal):
            def begin_execution(self, *args, **kwargs):
                begun = super().begin_execution(*args, **kwargs)
                def shadow_check(*args, **kwargs):
                    return None

                setattr(authority, "check_snapshot", shadow_check)
                return begun

        journal = SwappingJournal()
        kernel = _ProviderAutoApprovingKernel(
            provider=provider,
            broker=CapabilityBroker(tools=(tool,)),
            journal=journal,
            clock=FakeClock(),
            cancellation=FakeCancellation(),
            approval_authority=authority,
        )
        review = kernel.prepare_approval_review(request)
        decision = ExecutionApprovalDecision.create(
            review=review,
            reviewer_id="reviewer_local_01",
            outcome="approved",
            approved_tool_ids=("source.read",),
            expires_at_ms=2_000,
        )
        authority.decide(
            decision,
            expected_generation=0,
            expected_review_hash=review.content_hash,
        )

        with self.assertRaisesRegex(KernelError, "approval_authority_invalid"):
            kernel.execute(request)
        self.assertEqual(1, len(journal.begin_calls))
        self.assertEqual([], provider.requests)
        self.assertEqual([], tool.calls)

    def test_exact_snapshot_and_check_outputs_bind_to_minted_review_and_decision(self) -> None:
        review = _approval_review()
        decision = ExecutionApprovalDecision.create(
            review=review,
            reviewer_id="reviewer_local_01",
            outcome="approved",
            approved_tool_ids=("source.read",),
            expires_at_ms=2_000,
        )
        snapshot = ApprovalAuthoritySnapshot(
            review,
            decision,
            1,
            review.content_hash,
            decision.content_hash,
            "approved",
        )
        check = ApprovalCheck(
            review.content_hash,
            decision.content_hash,
            decision.approved_tool_ids,
        )
        self.assertEqual(
            snapshot,
            _validate_authority_snapshot_for_review(snapshot, review),
        )
        self.assertEqual(
            check,
            _validate_approval_check_for_snapshot(
                check, review, snapshot, now_ms=1_999
            ),
        )

        other = _approval_review(grant_hash="0" * 64)
        with self.assertRaisesRegex(ApprovalError, "approval_check_failed"):
            _validate_prepared_review_for_review(other, review)
        with self.assertRaisesRegex(ApprovalError, "approval_check_failed"):
            _validate_authority_snapshot_for_review(snapshot, other)
        for forged in (
            ApprovalCheck("0" * 64, decision.content_hash, ("source.read",)),
            ApprovalCheck(review.content_hash, "0" * 64, ("source.read",)),
            ApprovalCheck(review.content_hash, decision.content_hash, ("world.validate",)),
        ):
            with self.subTest(forged=forged):
                with self.assertRaisesRegex(ApprovalError, "approval_check_failed"):
                    _validate_approval_check_for_snapshot(
                        forged, review, snapshot, now_ms=1_999
                    )
        with self.assertRaisesRegex(ApprovalError, "approval_check_failed"):
            _validate_approval_check_for_snapshot(check, review, snapshot, now_ms=2_000)

    def test_forged_direct_authority_cannot_select_approval_evidence_or_execute(self) -> None:
        class ForgedAuthority(ExecutionApprovalAuthority):
            def __init__(self) -> None:
                self.review: ExecutionApprovalReview | None = None
                self.decision: ExecutionApprovalDecision | None = None

            def prepare(
                self, review: object, *, expected_generation: object
            ) -> ExecutionApprovalReview:
                assert type(review) is ExecutionApprovalReview
                self.review = review
                self.decision = ExecutionApprovalDecision.create(
                    review=review,
                    reviewer_id="attacker_local",
                    outcome="approved",
                    approved_tool_ids=("source.read",),
                    expires_at_ms=2_000,
                )
                return review

            def snapshot(self, review: object) -> ApprovalAuthoritySnapshot:
                assert self.review is not None and self.decision is not None
                return ApprovalAuthoritySnapshot(
                    self.review,
                    self.decision,
                    1,
                    self.review.content_hash,
                    self.decision.content_hash,
                    "approved",
                )

            def check_snapshot(
                self, review: object, expected: object, *, now_ms: object
            ) -> ApprovalCheck:
                assert self.review is not None and self.decision is not None
                return ApprovalCheck(
                    self.review.content_hash,
                    self.decision.content_hash,
                    ("source.read",),
                )

        activation, grant = _documents(capabilities=["tool.invoke"], tools=["source.read"])
        request = replace(_request(activation, grant), approval_id="approval_execution_01")
        provider = FakeProvider([ProviderTurnResult("done", _usage(), completed=True)])
        tool = FakeTool("source.read", "tool.invoke", ToolResult("unused"))
        journal = FakeJournal()
        try:
            kernel = _ProviderAutoApprovingKernel(
                provider=provider,
                broker=CapabilityBroker(tools=(tool,)),
                journal=journal,
                clock=FakeClock(),
                cancellation=FakeCancellation(),
                approval_authority=ForgedAuthority(),
            )
        except KernelError as exc:
            self.assertEqual("approval_authority_invalid", exc.reason_code)
            self.assertEqual([], journal.begin_calls)
            self.assertEqual([], provider.requests)
            self.assertEqual([], tool.calls)
            return

        kernel.prepare_approval_review(request)
        kernel.execute(request)
        self.fail(
            "forged authority reached effects: "
            f"journal={len(journal.begin_calls)} provider={len(provider.requests)}"
        )

    def test_direct_registry_insertion_cannot_authorize_forged_instance(self) -> None:
        class ForgedAuthority(ExecutionApprovalAuthority):
            def __init__(self) -> None:
                self.review: ExecutionApprovalReview | None = None
                self.decision: ExecutionApprovalDecision | None = None

            def prepare(self, review: object, *, expected_generation: object):
                assert type(review) is ExecutionApprovalReview
                self.review = review
                self.decision = ExecutionApprovalDecision.create(
                    review=review,
                    reviewer_id="attacker_local",
                    outcome="approved",
                    approved_tool_ids=("source.read",),
                    expires_at_ms=2_000,
                )
                return review

            def snapshot(self, review: object):
                assert self.review is not None and self.decision is not None
                return ApprovalAuthoritySnapshot(
                    self.review,
                    self.decision,
                    1,
                    self.review.content_hash,
                    self.decision.content_hash,
                    "approved",
                )

            def check_snapshot(self, review: object, expected: object, *, now_ms: object):
                assert self.review is not None and self.decision is not None
                return ApprovalCheck(
                    self.review.content_hash,
                    self.decision.content_hash,
                    self.decision.approved_tool_ids,
                )

        forged = ForgedAuthority()
        functions = _authority_functions(type(forged))
        self.assertFalse(
            hasattr(approvals_module, "_EXECUTION_APPROVAL_AUTHORITY_IDENTITIES")
        )
        setattr(
            approvals_module,
            "_EXECUTION_APPROVAL_AUTHORITY_IDENTITIES",
            {id(forged): (ref(forged), type(forged), functions)},
        )
        activation, grant = _documents(capabilities=["tool.invoke"], tools=["source.read"])
        request = replace(_request(activation, grant), approval_id="approval_execution_01")
        provider = FakeProvider([ProviderTurnResult("done", _usage(), completed=True)])
        journal = FakeJournal()
        try:
            try:
                kernel = _ProviderAutoApprovingKernel(
                    provider=provider,
                    broker=CapabilityBroker(
                        tools=(
                            FakeTool("source.read", "tool.invoke", ToolResult("unused")),
                        )
                    ),
                    journal=journal,
                    clock=FakeClock(),
                    cancellation=FakeCancellation(),
                    approval_authority=forged,
                )
            except KernelError as exc:
                self.assertEqual("approval_authority_invalid", exc.reason_code)
                self.assertEqual([], journal.begin_calls)
                self.assertEqual([], provider.requests)
                return
            kernel.prepare_approval_review(request)
            kernel.execute(request)
            self.fail(
                "direct registry insertion reached effects: "
                f"journal={len(journal.begin_calls)} provider={len(provider.requests)}"
            )
        finally:
            delattr(approvals_module, "_EXECUTION_APPROVAL_AUTHORITY_IDENTITIES")

    def test_shape_only_approval_authority_is_rejected(self) -> None:
        class ShapeOnlyAuthority:
            def prepare(self, review, *, expected_generation):
                return review

            def snapshot(self, review):
                return None

            def check_snapshot(self, review, expected, *, now_ms):
                return None

        with tempfile.TemporaryDirectory() as temporary, AgentEventLog(
            Path(temporary) / "events"
        ) as event_log:
            with self.assertRaisesRegex(KernelError, "approval_authority_invalid"):
                _ProviderAutoApprovingKernel(
                    provider=FakeProvider([]),
                    broker=CapabilityBroker(),
                    journal=event_log,
                    clock=FakeClock(),
                    cancellation=FakeCancellation(),
                    approval_authority=ShapeOnlyAuthority(),
                )

    def test_authority_snapshot_is_checked_immediately_before_and_after_journal_begin(
        self,
    ) -> None:
        order: list[str] = []

        class OrderedKernel(_ProviderAutoApprovingKernel):
            def _approval_state(self, *args, **kwargs):
                result = super()._approval_state(*args, **kwargs)
                order.append("check")
                return result

        class OrderedJournal(AgentEventLog):
            def begin_execution(self, *args, **kwargs):
                order.append("begin")
                return super().begin_execution(*args, **kwargs)

        activation, grant = _documents(capabilities=["tool.invoke"], tools=["source.read"])
        request = replace(_request(activation, grant), approval_id="approval_execution_01")
        authority = InMemoryHumanApprovalAuthority()
        with tempfile.TemporaryDirectory() as temporary, OrderedJournal(
            Path(temporary) / "events"
        ) as event_log:
            kernel = OrderedKernel(
                provider=FakeProvider(
                    [ProviderTurnResult("done", _usage(), completed=True)]
                ),
                broker=CapabilityBroker(
                    tools=(FakeTool("source.read", "tool.invoke", ToolResult("unused")),)
                ),
                journal=event_log,
                clock=FakeClock(),
                cancellation=FakeCancellation(),
                approval_authority=authority,
            )
            review = kernel.prepare_approval_review(request)
            decision = ExecutionApprovalDecision.create(
                review=review,
                reviewer_id="reviewer_local_01",
                outcome="approved",
                approved_tool_ids=("source.read",),
                expires_at_ms=2_000,
            )
            authority.decide(
                decision,
                expected_generation=0,
                expected_review_hash=review.content_hash,
            )

            self.assertEqual("succeeded", kernel.execute(request).outcome)
            self.assertEqual(["check", "begin", "check"], order[:3])

    def test_durable_director_authority_prepares_approves_and_executes(self) -> None:
        activation, grant = _documents(capabilities=["tool.invoke"], tools=["source.read"])
        request = replace(_request(activation, grant), approval_id="approval_execution_01")
        provider = FakeProvider([ProviderTurnResult("done", _usage(), completed=True)])
        tool = FakeTool("source.read", "tool.invoke", ToolResult("unused"))

        with tempfile.TemporaryDirectory() as temporary:
            store = StudioStore(Path(temporary) / "studio")
            try:
                authority = StudioAuthenticatedHumanDecisionAuthority.enroll(
                    store,
                    passphrase=_PASSPHRASE,
                )
                with AgentEventLog(Path(temporary) / "events") as event_log:
                    kernel = _ProviderAutoApprovingKernel(
                        provider=provider,
                        broker=CapabilityBroker(tools=(tool,)),
                        journal=event_log,
                        clock=FakeClock(),
                        cancellation=FakeCancellation(),
                        approval_authority=authority,
                    )
                    review = kernel.prepare_approval_review(request)
                    decision = ExecutionApprovalDecision.create(
                        review=review,
                        reviewer_id="director_local",
                        outcome="approved",
                        approved_tool_ids=("source.read",),
                        expires_at_ms=2_000,
                    )
                    authority.decide(
                        decision,
                        expected_generation=0,
                        expected_review_hash=review.content_hash,
                    )

                    execution = AgentExecutionCoordinator(
                        kernel=kernel,
                        event_log=event_log,
                    ).execute(request)

                    self.assertEqual("executed", execution.disposition)
                    self.assertEqual("succeeded", execution.result.outcome)
                    self.assertEqual(1, len(provider.requests))
                    self.assertEqual([], tool.calls)
                    self.assertEqual("terminal", execution.records.state)
                    self.assertIsNotNone(execution.records.request_fingerprint)
            finally:
                store.close()

    def test_restart_unlock_replays_terminal_after_revocation_without_new_effects(
        self,
    ) -> None:
        activation, grant = _documents(capabilities=["tool.invoke"], tools=["source.read"])
        request = replace(_request(activation, grant), approval_id="approval_execution_01")
        with tempfile.TemporaryDirectory() as temporary:
            studio_path = Path(temporary) / "studio"
            event_path = Path(temporary) / "events"
            provider = FakeProvider([ProviderTurnResult("done", _usage(), completed=True)])
            tool = FakeTool("source.read", "tool.invoke", ToolResult("unused"))
            store = StudioStore(studio_path)
            try:
                authority = StudioAuthenticatedHumanDecisionAuthority.enroll(
                    store, passphrase=_PASSPHRASE
                )
                with AgentEventLog(event_path) as event_log:
                    kernel = _ProviderAutoApprovingKernel(
                        provider=provider,
                        broker=CapabilityBroker(tools=(tool,)),
                        journal=event_log,
                        clock=FakeClock(),
                        cancellation=FakeCancellation(),
                        approval_authority=authority,
                    )
                    review = kernel.prepare_approval_review(request)
                    decision = ExecutionApprovalDecision.create(
                        review=review,
                        reviewer_id="director_local",
                        outcome="approved",
                        approved_tool_ids=("source.read",),
                        expires_at_ms=2_000,
                    )
                    authority.decide(
                        decision,
                        expected_generation=0,
                        expected_review_hash=review.content_hash,
                    )
                    first = AgentExecutionCoordinator(
                        kernel=kernel, event_log=event_log
                    ).execute(request)
                    first_fingerprint = first.records.request_fingerprint
                store.close()

                store = StudioStore(studio_path)
                restarted = StudioAuthenticatedHumanDecisionAuthority.unlock(
                    store, passphrase=_PASSPHRASE
                )
                restarted.revoke(
                    review.approval_id,
                    expected_generation=1,
                    expected_decision_hash=decision.content_hash,
                )
                replay_provider = FakeProvider([])
                with AgentEventLog(event_path) as event_log:
                    replay_kernel = _ProviderAutoApprovingKernel(
                        provider=replay_provider,
                        broker=CapabilityBroker(tools=(tool,)),
                        journal=event_log,
                        clock=FakeClock(),
                        cancellation=FakeCancellation(),
                        approval_authority=restarted,
                    )
                    duplicate = AgentExecutionCoordinator(
                        kernel=replay_kernel, event_log=event_log
                    ).execute(request)
                    self.assertEqual("existing_terminal", duplicate.disposition)
                    self.assertEqual(first_fingerprint, duplicate.records.request_fingerprint)
                    self.assertEqual([], replay_provider.requests)
                    self.assertEqual([], tool.calls)
            finally:
                store.close()

            event_bytes = b"".join(
                path.read_bytes() for path in event_path.iterdir() if path.is_file()
            )
            self.assertNotIn(_PASSPHRASE.encode("utf-8"), event_bytes)
            self.assertNotIn(b"director_local", event_bytes)
            self.assertNotIn(decision.content_hash.encode("ascii"), event_bytes)

    def test_stale_request_and_late_decision_are_not_authorized(self) -> None:
        activation, grant = _documents(capabilities=["tool.invoke"], tools=["source.read"])
        request = replace(_request(activation, grant), approval_id="approval_execution_01")
        provider = FakeProvider([])
        tool = FakeTool("source.read", "tool.invoke", ToolResult("unused"))
        with tempfile.TemporaryDirectory() as temporary:
            store = StudioStore(Path(temporary) / "studio")
            try:
                authority = StudioAuthenticatedHumanDecisionAuthority.enroll(
                    store, passphrase=_PASSPHRASE
                )
                holder: dict[str, object] = {}

                class DecidingJournal(AgentEventLog):
                    def begin_execution(self, *args, **kwargs):
                        begun = super().begin_execution(*args, **kwargs)
                        if begun:
                            authority.decide(
                                holder["decision"],
                                expected_generation=0,
                                expected_review_hash=holder["review"].content_hash,
                            )
                        return begun

                with DecidingJournal(Path(temporary) / "late-events") as event_log:
                    kernel = _ProviderAutoApprovingKernel(
                        provider=provider,
                        broker=CapabilityBroker(tools=(tool,)),
                        journal=event_log,
                        clock=FakeClock(),
                        cancellation=FakeCancellation(),
                        approval_authority=authority,
                    )
                    review = kernel.prepare_approval_review(request)
                    holder["review"] = review
                    holder["decision"] = ExecutionApprovalDecision.create(
                        review=review,
                        reviewer_id="director_local",
                        outcome="approved",
                        approved_tool_ids=("source.read",),
                        expires_at_ms=2_000,
                    )
                    result = kernel.execute(request)
                    self.assertEqual(["tool_not_authorized"], result.receipt["failure_codes"])
                    self.assertEqual([], provider.requests)

                drifted = replace(request, private_input={"prompt": "changed"})
                with AgentEventLog(Path(temporary) / "stale-events") as event_log:
                    drift_kernel = _ProviderAutoApprovingKernel(
                        provider=provider,
                        broker=CapabilityBroker(tools=(tool,)),
                        journal=event_log,
                        clock=FakeClock(),
                        cancellation=FakeCancellation(),
                        approval_authority=authority,
                    )
                    drift_result = drift_kernel.execute(drifted)
                    self.assertEqual(
                        ["tool_not_authorized"], drift_result.receipt["failure_codes"]
                    )
                    self.assertEqual([], provider.requests)
                    self.assertEqual([], tool.calls)
            finally:
                store.close()

    def test_durable_revocation_during_begin_blocks_provider_and_tool_effects(self) -> None:
        activation, grant = _documents(capabilities=["tool.invoke"], tools=["source.read"])
        request = replace(_request(activation, grant), approval_id="approval_execution_01")
        provider = FakeProvider([])
        tool = FakeTool("source.read", "tool.invoke", ToolResult("unused"))
        with tempfile.TemporaryDirectory() as temporary:
            studio_path = Path(temporary) / "studio"
            store = StudioStore(studio_path)
            revoker_store: StudioStore | None = None
            try:
                authority = StudioAuthenticatedHumanDecisionAuthority.enroll(
                    store, passphrase=_PASSPHRASE
                )
                holder: dict[str, object] = {}

                class RevokingJournal(AgentEventLog):
                    def begin_execution(self, *args, **kwargs):
                        begun = super().begin_execution(*args, **kwargs)
                        if begun:
                            revoker.revoke(
                                holder["review"].approval_id,
                                expected_generation=1,
                                expected_decision_hash=holder["decision"].content_hash,
                            )
                        return begun

                with RevokingJournal(Path(temporary) / "events") as event_log:
                    kernel = _ProviderAutoApprovingKernel(
                        provider=provider,
                        broker=CapabilityBroker(tools=(tool,)),
                        journal=event_log,
                        clock=FakeClock(),
                        cancellation=FakeCancellation(),
                        approval_authority=authority,
                    )
                    review = kernel.prepare_approval_review(request)
                    decision = ExecutionApprovalDecision.create(
                        review=review,
                        reviewer_id="director_local",
                        outcome="approved",
                        approved_tool_ids=("source.read",),
                        expires_at_ms=2_000,
                    )
                    authority.decide(
                        decision,
                        expected_generation=0,
                        expected_review_hash=review.content_hash,
                    )
                    revoker_store = StudioStore(studio_path, mode="secondary")
                    revoker = StudioAuthenticatedHumanDecisionAuthority.unlock(
                        revoker_store, passphrase=_PASSPHRASE
                    )
                    holder.update(review=review, decision=decision)

                    result = kernel.execute(request)

                    self.assertEqual(["tool_not_authorized"], result.receipt["failure_codes"])
                    self.assertEqual([], provider.requests)
                    self.assertEqual([], tool.calls)
            finally:
                if revoker_store is not None:
                    revoker_store.close()
                store.close()


if __name__ == "__main__":
    unittest.main()
