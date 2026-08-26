from __future__ import annotations

import hashlib
import hmac
import json
import multiprocessing
import os
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

from tests.agent_harness_fakes import FakeCancellation, FakeClock
from tests.test_agent_execution_kernel import _documents, _kernel, _request
from worldforge.agent_harness import OneShotProviderSupervisor
from worldforge.agent_harness import process_supervisor as process_supervisor_module
from worldforge.agent_harness import worker as worker_module
from worldforge.agent_harness import worker_registry as worker_registry_module
from worldforge.agent_harness.event_log import AgentEventLog, AgentExecutionCoordinator
from worldforge.agent_harness.kernel import AgentExecutionKernel
from worldforge.agent_harness.ports import (
    ProviderBoundaryControl,
    ProviderTurnRequest,
    ProviderTurnResult,
    ProviderUsage,
)
from worldforge.agent_harness.process_supervisor import (
    ProviderBoundaryFailure,
    ProviderBoundaryIndeterminate,
    ProviderBoundaryStopped,
    ProviderBoundaryUnsupported,
    fixed_worker_command,
)
from worldforge.agent_harness.worker_protocol import (
    MAX_WORKER_REQUEST_BYTES,
    WorkerProtocolError,
    build_request_frame,
    build_result_frame,
    parse_request_frame,
    parse_result_frame,
)
from worldforge.agent_harness.worker_registry import fixed_runtime_identity


def _turn_request(private_input: object) -> ProviderTurnRequest:
    return ProviderTurnRequest(
        execution_id="execution_minimal_01",
        turn_index=0,
        private_input=private_input,
        history=(),
    )


def _control(reason: str | None = None) -> ProviderBoundaryControl:
    return ProviderBoundaryControl(lambda: reason)


def _case(action: str = "echo", **values: object) -> dict[str, object]:
    return {"__worldforge_conformance__": {"action": action, **values}}


def _fake_retained_identity(
    pid: int, start_time: int | None
) -> process_supervisor_module._ProcessIdentity:
    return process_supervisor_module._ProcessIdentity(pid, start_time or 1)


def _authenticated_frame(document: dict[str, object], key: bytes) -> bytes:
    body = {name: value for name, value in document.items() if name != "mac"}
    canonical = json.dumps(
        body,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    document["mac"] = hmac.new(key, canonical, hashlib.sha256).hexdigest()
    payload = json.dumps(
        document,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return len(payload).to_bytes(4, "big") + payload


def _frame_document(frame: bytes) -> dict[str, object]:
    return json.loads(frame[4:].decode("utf-8"))


_NO_READY_DESCENDANT_PATH: str | None = None


def _slow_no_ready_broker(
    control: object,
    _broker_key: bytes,
    _broker_nonce: str,
    _worker_key: bytes,
    _request_frame: bytes,
    _scratch: str,
) -> None:
    """Fork-only test broker that never reaches the authenticated ready gate."""

    child = os.fork()
    if child == 0:
        time.sleep(30)
        os._exit(0)
    assert _NO_READY_DESCENDANT_PATH is not None
    Path(_NO_READY_DESCENDANT_PATH).write_text(str(child), encoding="ascii")
    time.sleep(0.3)
    control.close()


def _linux_descendants(root_pid: int) -> set[int]:
    table: dict[int, int] = {}
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            raw = (entry / "stat").read_text(encoding="ascii")
            fields = raw[raw.rfind(")") + 2 :].split()
            table[int(entry.name)] = int(fields[1])
        except (FileNotFoundError, ProcessLookupError, OSError, ValueError, IndexError):
            continue
    result: set[int] = set()
    changed = True
    while changed:
        changed = False
        for pid, parent in table.items():
            if pid not in result and (parent == root_pid or parent in result):
                result.add(pid)
                changed = True
    return result


class _RealtimeClock:
    def __init__(self, now_ms: int = 1_000) -> None:
        self._origin = time.monotonic()
        self._now_ms = now_ms

    def now_ms(self) -> int:
        return self._now_ms + int((time.monotonic() - self._origin) * 1_000)


class _RealtimeCancellation:
    def __init__(self, after_ms: int) -> None:
        self._origin = time.monotonic()
        self._after_ms = after_ms

    def is_cancelled(self) -> bool:
        return (time.monotonic() - self._origin) * 1_000 >= self._after_ms


@unittest.skipUnless(sys.platform.startswith("linux"), "real containment probe is Linux-only")
class LinuxOneShotProviderSupervisorTests(unittest.TestCase):
    def test_supervisor_exposes_fresh_exact_bootstrap_runtime_binding(self) -> None:
        supervisor = OneShotProviderSupervisor(turn_timeout_ms=2_000)
        first = supervisor.runtime_binding
        self.assertEqual(fixed_runtime_identity(), first)
        first["id"] = "caller_mutation"
        self.assertEqual(fixed_runtime_identity(), supervisor.runtime_binding)

    def test_mutated_runtime_results_cannot_retarget_actual_worker_receipt(self) -> None:
        expected = fixed_runtime_identity()
        supervisor = OneShotProviderSupervisor(turn_timeout_ms=2_000)
        key = b"k" * 32
        parsed = parse_request_frame(
            build_request_frame(_turn_request({"value": 1}), key=key, nonce="ab" * 32),
            key=key,
        )
        exposed_documents = [
            fixed_runtime_identity(),
            supervisor.runtime_binding,
            parsed.runtime,
        ]
        for document in exposed_documents:
            document.clear()
            document.update(
                id="caller_selected_runtime",
                revision=2,
                content_hash="f" * 64,
            )

        activation, grant = _documents()
        result = _kernel(supervisor)[0].execute(
            replace(
                _request(activation, grant),
                private_input=_case("echo", payload="actual_runtime"),
            )
        )

        self.assertEqual("succeeded", result.outcome)
        self.assertEqual(expected, result.receipt["runtime_binding"])
        result.receipt["runtime_binding"].clear()
        self.assertEqual(expected, fixed_runtime_identity())
        self.assertEqual(expected, supervisor.runtime_binding)

    def test_request_protocol_is_canonical_authenticated_bounded_and_exact(self) -> None:
        key = b"k" * 32
        nonce = "ab" * 32
        request = _turn_request({"private": "payload"})
        frame = build_request_frame(request, key=key, nonce=nonce)
        self.assertLessEqual(len(frame), MAX_WORKER_REQUEST_BYTES + 4)
        parsed = parse_request_frame(frame, key=key)
        self.assertEqual(request, parsed.request)
        self.assertEqual(nonce, parsed.nonce)
        self.assertEqual(fixed_runtime_identity(), parsed.runtime)

        payload = frame[4:]
        mutated = len(payload + b" ").to_bytes(4, "big") + payload + b" "
        with self.assertRaisesRegex(WorkerProtocolError, "worker_protocol_noncanonical"):
            parse_request_frame(mutated, key=key)
        duplicate = payload.replace(b'{"format":', b'{"format":"duplicate","format":', 1)
        with self.assertRaisesRegex(WorkerProtocolError, "worker_protocol_duplicate_key"):
            parse_request_frame(len(duplicate).to_bytes(4, "big") + duplicate, key=key)
        with self.assertRaisesRegex(WorkerProtocolError, "worker_protocol_authentication_failed"):
            parse_request_frame(frame, key=b"z" * 32)
        with self.assertRaisesRegex(WorkerProtocolError, "worker_protocol_trailing_bytes"):
            parse_request_frame(frame + frame, key=key)
        with self.assertRaisesRegex(WorkerProtocolError, "worker_protocol_invalid"):
            build_request_frame(
                _turn_request(("not", "an", "exact-json-container")),
                key=key,
                nonce=nonce,
            )

    def test_private_protocol_rejects_bool_versions_and_non_sha_request_hashes(
        self,
    ) -> None:
        key = b"k" * 32
        nonce = "ab" * 32
        request_frame = build_request_frame(_turn_request({"value": 1}), key=key, nonce=nonce)

        request_mutations = (
            ("format_version", lambda document: document.__setitem__("format_version", True)),
            (
                "runtime_revision",
                lambda document: document["runtime"].__setitem__("revision", True),
            ),
        )
        for label, mutate in request_mutations:
            with self.subTest(request=label):
                document = _frame_document(request_frame)
                mutate(document)
                with self.assertRaises(WorkerProtocolError):
                    parse_request_frame(_authenticated_frame(document, key), key=key)

        request_hash = _frame_document(request_frame)["request_hash"]
        assert type(request_hash) is str
        result = ProviderTurnResult(
            private_output={"answer": 42},
            usage=ProviderUsage(1, 1, 0, 0, "USD"),
            completed=True,
        )
        result_frame = build_result_frame(
            result,
            key=key,
            nonce=nonce,
            request_hash=request_hash,
        )
        result_mutations: tuple[tuple[str, object], ...] = (
            ("bool", True),
            ("uppercase", request_hash.upper()),
        )
        for label, invalid_hash in result_mutations:
            with self.subTest(result_request_hash=label):
                document = _frame_document(result_frame)
                document["request_hash"] = invalid_hash
                with self.assertRaisesRegex(
                    WorkerProtocolError, "worker_protocol_correlation_failed"
                ):
                    parse_result_frame(
                        _authenticated_frame(document, key),
                        key=key,
                        nonce=nonce,
                        request_hash=invalid_hash,  # type: ignore[arg-type]
                    )

        for field in ("format_version", "runtime_revision"):
            with self.subTest(result=field):
                document = _frame_document(result_frame)
                if field == "format_version":
                    document["format_version"] = True
                else:
                    document["runtime"]["revision"] = True
                with self.assertRaises(WorkerProtocolError):
                    parse_result_frame(
                        _authenticated_frame(document, key),
                        key=key,
                        nonce=nonce,
                        request_hash=request_hash,
                    )

    def test_worker_rejects_trailing_or_second_request_before_execution(self) -> None:
        key = b"w" * 32
        nonce = "cd" * 32
        frame = build_request_frame(
            _turn_request(_case("echo", payload="must-not-run")),
            key=key,
            nonce=nonce,
        )
        bool_version = _frame_document(frame)
        bool_version["format_version"] = True
        malformed_inputs = (
            ("trailing_byte", key + frame + b"x"),
            ("second_frame", key + frame + frame),
            ("bool_version", key + _authenticated_frame(bool_version, key)),
        )
        for label, payload in malformed_inputs:
            with self.subTest(case=label):
                completed = subprocess.run(
                    fixed_worker_command(),
                    input=payload,
                    capture_output=True,
                    timeout=2,
                    check=False,
                )
                self.assertEqual(70, completed.returncode)
                self.assertEqual(b"", completed.stdout)
                self.assertEqual(b"", completed.stderr)

    def test_fresh_child_result_is_released_only_after_its_process_is_gone(self) -> None:
        supervisor = OneShotProviderSupervisor(turn_timeout_ms=2_000)
        result = supervisor.turn(
            _turn_request(_case("echo", payload={"answer": 42}, include_worker_pid=True)),
            boundary=_control(),
        )
        self.assertEqual({"answer": 42}, result.private_output["payload"])
        worker_pid = result.private_output["worker_pid"]
        self.assertNotEqual(os.getpid(), worker_pid)
        self.assertFalse(Path(f"/proc/{worker_pid}").exists())
        self.assertEqual(1, supervisor.spawn_count)

    def test_conformance_runtime_carries_usage_and_parent_kernel_enforces_budget(self) -> None:
        activation, grant = _documents()
        supervisor = OneShotProviderSupervisor(turn_timeout_ms=2_000)
        request = _request(activation, grant, max_total_tokens=4)
        request = request.__class__(
            activation=request.activation,
            grant=request.grant,
            log_id=request.log_id,
            receipt_id=request.receipt_id,
            event_id_prefix=request.event_id_prefix,
            invocation_id_prefix=request.invocation_id_prefix,
            limits=request.limits,
            private_input=_case(
                "echo",
                payload="private",
                usage={
                    "input_tokens": 3,
                    "output_tokens": 2,
                    "cached_input_tokens": 1,
                    "cost_minor_units": 0,
                    "currency": "USD",
                },
            ),
        )
        result = _kernel(supervisor)[0].execute(request)
        self.assertEqual("failed", result.outcome)
        self.assertEqual(["token_budget_exceeded"], result.receipt["failure_codes"])
        self.assertEqual(
            5,
            result.receipt["usage"]["input_tokens"] + result.receipt["usage"]["output_tokens"],
        )
        self.assertEqual(supervisor.runtime_binding, result.receipt["runtime_binding"])

        cost_supervisor = OneShotProviderSupervisor(turn_timeout_ms=2_000)
        cost_result = _kernel(cost_supervisor)[0].execute(
            replace(
                _request(activation, grant),
                private_input=_case(
                    "echo",
                    usage={
                        "input_tokens": 1,
                        "output_tokens": 1,
                        "cached_input_tokens": 0,
                        "cost_minor_units": 11,
                        "currency": "USD",
                    },
                ),
            )
        )
        self.assertEqual(["cost_budget_exceeded"], cost_result.receipt["failure_codes"])
        self.assertEqual(11, cost_result.receipt["usage"]["cost_minor_units"])

    def test_kernel_maps_proven_empty_stop_reasons_and_private_timeout(self) -> None:
        activation, grant = _documents()
        cases = (
            (
                _RealtimeClock(),
                _RealtimeCancellation(50),
                {"max_duration_ms": 1_000, "deadline_ms": 5_000},
                2_000,
                "cancelled",
                "execution_cancelled",
            ),
            (
                _RealtimeClock(),
                FakeCancellation(),
                {"max_duration_ms": 1_000, "deadline_ms": 1_050},
                2_000,
                "cancelled",
                "execution_deadline_exceeded",
            ),
            (
                _RealtimeClock(),
                FakeCancellation(),
                {"max_duration_ms": 40, "deadline_ms": None},
                2_000,
                "cancelled",
                "duration_budget_exceeded",
            ),
            (
                _RealtimeClock(),
                FakeCancellation(),
                {"max_duration_ms": 1_000, "deadline_ms": 5_000},
                30,
                "failed",
                "provider_failed",
            ),
        )
        for clock, cancellation, limits, timeout, outcome, reason in cases:
            with self.subTest(reason=reason):
                supervisor = OneShotProviderSupervisor(turn_timeout_ms=timeout)
                kernel, _journal = _kernel(
                    supervisor,
                    clock=clock,
                    cancellation=cancellation,
                )
                result = kernel.execute(
                    replace(
                        _request(activation, grant, **limits),
                        private_input=_case("sleep", milliseconds=500),
                    )
                )
                self.assertEqual(outcome, result.outcome)
                self.assertEqual([reason], result.receipt["failure_codes"])

    def test_poll_order_maps_cancellation_deadline_duration_and_turn_timeout(self) -> None:
        for reason in (
            "execution_cancelled",
            "execution_deadline_exceeded",
            "duration_budget_exceeded",
        ):
            with self.subTest(reason=reason):
                supervisor = OneShotProviderSupervisor(turn_timeout_ms=1_000)
                with self.assertRaises(ProviderBoundaryStopped) as raised:
                    supervisor.turn(
                        _turn_request(_case("sleep", milliseconds=500)),
                        boundary=_control(reason),
                    )
                self.assertEqual(reason, raised.exception.reason_code)
        supervisor = OneShotProviderSupervisor(turn_timeout_ms=30)
        with self.assertRaisesRegex(ProviderBoundaryFailure, "provider_failed"):
            supervisor.turn(
                _turn_request(_case("sleep", milliseconds=500)),
                boundary=_control(),
            )

        checks = 0

        def cancel_before_release() -> str | None:
            nonlocal checks
            checks += 1
            return "execution_cancelled" if checks >= 2 else None

        gated = OneShotProviderSupervisor(turn_timeout_ms=1_000)
        with self.assertRaises(ProviderBoundaryStopped):
            gated.turn(
                _turn_request(_case("stderr")),
                boundary=ProviderBoundaryControl(cancel_before_release),
            )
        self.assertEqual(1, gated.spawn_count)

    def test_linux_rechecks_stop_after_ready_identity_before_release(self) -> None:
        broker_key = b"b" * 32
        broker_nonce_bytes = b"n" * 32
        broker_nonce = broker_nonce_bytes.hex()
        ready = process_supervisor_module._encode_control(
            kind="ready",
            sequence=0,
            nonce=broker_nonce,
            payload={"worker_pid": 42_002, "worker_start_time": 92},
            key=broker_key,
        )
        domain_empty = process_supervisor_module._encode_control(
            kind="domain_empty",
            sequence=1,
            nonce=broker_nonce,
            payload={"status": "cancelled"},
            key=broker_key,
        )

        class FakeSocket:
            def __init__(self, incoming: bytes = b"") -> None:
                self.incoming = bytearray(incoming)
                self.sent = bytearray()

            def recv(self, count: int) -> bytes:
                if not self.incoming:
                    raise BlockingIOError
                chunk = bytes(self.incoming[:count])
                del self.incoming[:count]
                return chunk

            def send(self, payload: object) -> int:
                raw = bytes(payload)
                self.sent.extend(raw)
                return len(raw)

            def setblocking(self, _blocking: bool) -> None:
                pass

            def close(self) -> None:
                pass

        class FakeProcess:
            pid = 42_001

            def __init__(self) -> None:
                self.alive = True

            def start(self) -> None:
                pass

            def join(self, _timeout: float) -> None:
                self.alive = False

            def is_alive(self) -> bool:
                return self.alive

        parent = FakeSocket(ready + domain_empty)
        child = FakeSocket()
        process = FakeProcess()
        context = mock.Mock()
        context.Process.return_value = process
        polls = 0

        def stop_only_at_final_gate() -> str | None:
            nonlocal polls
            polls += 1
            return "execution_cancelled" if polls >= 3 else None

        key = b"w" * 32
        frame = build_request_frame(_turn_request({"no": "execution"}), key=key, nonce="56" * 32)
        supervisor = process_supervisor_module.LinuxProcessSupervisor()
        start = process_supervisor_module._encode_control(
            kind="start",
            sequence=0,
            nonce=broker_nonce,
            payload={},
            key=broker_key,
        )
        with (
            mock.patch.object(
                process_supervisor_module.socket,
                "socketpair",
                return_value=(parent, child),
            ),
            mock.patch.object(
                process_supervisor_module.os,
                "urandom",
                side_effect=(broker_key, broker_nonce_bytes),
            ),
            mock.patch.object(
                process_supervisor_module.multiprocessing,
                "get_context",
                return_value=context,
            ),
            mock.patch.object(
                process_supervisor_module,
                "_retain_linux_identity",
                side_effect=_fake_retained_identity,
            ),
            mock.patch.object(
                process_supervisor_module,
                "_cleanup_linux_broker_domain",
                return_value=True,
            ) as cleanup,
            self.assertRaisesRegex(ProviderBoundaryStopped, "execution_cancelled"),
        ):
            supervisor.execute(
                frame,
                worker_key=key,
                boundary=ProviderBoundaryControl(stop_only_at_final_gate),
                turn_timeout_ms=1_000,
            )

        self.assertEqual(start, parent.sent)
        self.assertEqual(3, polls)
        cleanup.assert_called_once()

        parent = FakeSocket(ready + domain_empty)
        child = FakeSocket()
        process = FakeProcess()
        context.Process.return_value = process
        with (
            mock.patch.object(
                process_supervisor_module.socket,
                "socketpair",
                return_value=(parent, child),
            ),
            mock.patch.object(
                process_supervisor_module.os,
                "urandom",
                side_effect=(broker_key, broker_nonce_bytes),
            ),
            mock.patch.object(
                process_supervisor_module.multiprocessing,
                "get_context",
                return_value=context,
            ),
            mock.patch.object(
                process_supervisor_module,
                "_retain_linux_identity",
                side_effect=_fake_retained_identity,
            ),
            mock.patch.object(
                process_supervisor_module,
                "_cleanup_linux_broker_domain",
                return_value=True,
            ) as cleanup,
            mock.patch.object(
                process_supervisor_module.time,
                "monotonic",
                side_effect=(0.0, 0.0, 0.0, 2.0),
            ),
            self.assertRaisesRegex(ProviderBoundaryFailure, "provider_failed"),
        ):
            supervisor.execute(
                frame,
                worker_key=key,
                boundary=_control(),
                turn_timeout_ms=1_000,
            )
        self.assertEqual(start, parent.sent)
        cleanup.assert_called_once()

    def test_base_exception_from_parent_control_is_re_raised_only_after_cleanup(self) -> None:
        class StopNow(BaseException):
            pass

        checks = 0

        def poll() -> str | None:
            nonlocal checks
            checks += 1
            if checks >= 4:
                raise StopNow()
            return None

        supervisor = OneShotProviderSupervisor(turn_timeout_ms=2_000)
        with self.assertRaises(StopNow):
            supervisor.turn(
                _turn_request(_case("sleep", milliseconds=500)),
                boundary=ProviderBoundaryControl(poll),
            )
        self.assertIsNone(supervisor.active_broker_pid)

    def test_exception_from_parent_control_maps_failure_only_after_cleanup(self) -> None:
        checks = 0

        def poll() -> str | None:
            nonlocal checks
            checks += 1
            if checks >= 4:
                raise RuntimeError("private callback failure")
            return None

        supervisor = OneShotProviderSupervisor(turn_timeout_ms=2_000)
        with self.assertRaisesRegex(ProviderBoundaryFailure, "provider_failed"):
            supervisor.turn(
                _turn_request(_case("sleep", milliseconds=500)),
                boundary=ProviderBoundaryControl(poll),
            )
        self.assertIsNone(supervisor.active_broker_pid)

    def test_linux_latches_first_parent_control_outcome_without_repolling(self) -> None:
        class StopNow(BaseException):
            pass

        broker_key = b"l" * 32
        broker_nonce_bytes = b"m" * 32
        broker_nonce = broker_nonce_bytes.hex()
        ready = process_supervisor_module._encode_control(
            kind="ready",
            sequence=0,
            nonce=broker_nonce,
            payload={"worker_pid": 43_002, "worker_start_time": 102},
            key=broker_key,
        )
        domain_empty = process_supervisor_module._encode_control(
            kind="domain_empty",
            sequence=1,
            nonce=broker_nonce,
            payload={"status": "cancelled"},
            key=broker_key,
        )

        class FakeSocket:
            def __init__(self) -> None:
                self.actions: list[bytes | BaseException] = [
                    ready,
                    BlockingIOError(),
                    BlockingIOError(),
                    domain_empty,
                    b"",
                ]
                self.sent = bytearray()

            def recv(self, _count: int) -> bytes:
                if not self.actions:
                    return b""
                action = self.actions.pop(0)
                if isinstance(action, BaseException):
                    raise action
                return action

            def send(self, payload: object) -> int:
                raw = bytes(payload)
                self.sent.extend(raw)
                return len(raw)

            def setblocking(self, _blocking: bool) -> None:
                pass

            def close(self) -> None:
                pass

        class FakeChild:
            def close(self) -> None:
                pass

        class FakeProcess:
            pid = 43_001

            def __init__(self) -> None:
                self.alive = True

            def start(self) -> None:
                pass

            def join(self, _timeout: float) -> None:
                self.alive = False

            def is_alive(self) -> bool:
                return self.alive

        key = b"w" * 32
        frame = build_request_frame(_turn_request({"no": "execution"}), key=key, nonce="78" * 32)
        cases: tuple[tuple[str, object, object, type[BaseException]], ...] = (
            (
                "ordinary_exception",
                RuntimeError("first ordinary"),
                StopNow("must not overwrite ordinary"),
                ProviderBoundaryFailure,
            ),
            (
                "stop_reason",
                "execution_deadline_exceeded",
                StopNow("must not overwrite stop"),
                ProviderBoundaryStopped,
            ),
            (
                "base_exception",
                StopNow("first base"),
                RuntimeError("must not overwrite base"),
                StopNow,
            ),
        )
        for label, first, later, expected in cases:
            with self.subTest(case=label):
                parent = FakeSocket()
                process = FakeProcess()
                context = mock.Mock()
                context.Process.return_value = process
                polls = 0

                def poll(
                    first_outcome: object = first,
                    later_outcome: object = later,
                    trigger: int = 3 if label == "base_exception" else 4,
                ) -> str | None:
                    nonlocal polls
                    polls += 1
                    if polls < trigger:
                        return None
                    outcome = first_outcome if polls == trigger else later_outcome
                    if isinstance(outcome, BaseException):
                        raise outcome
                    return outcome  # type: ignore[return-value]

                supervisor = process_supervisor_module.LinuxProcessSupervisor()
                with (
                    mock.patch.object(
                        process_supervisor_module.socket,
                        "socketpair",
                        return_value=(parent, FakeChild()),
                    ),
                    mock.patch.object(
                        process_supervisor_module.os,
                        "urandom",
                        side_effect=(broker_key, broker_nonce_bytes),
                    ),
                    mock.patch.object(
                        process_supervisor_module.multiprocessing,
                        "get_context",
                        return_value=context,
                    ),
                    mock.patch.object(
                        process_supervisor_module,
                        "_retain_linux_identity",
                        side_effect=_fake_retained_identity,
                    ),
                    mock.patch.object(
                        process_supervisor_module,
                        "_cleanup_linux_broker_domain",
                        return_value=label != "base_exception",
                    ),
                    self.assertRaises(expected) as raised,
                ):
                    supervisor.execute(
                        frame,
                        worker_key=key,
                        boundary=ProviderBoundaryControl(poll),
                        turn_timeout_ms=1_000,
                    )
                self.assertEqual(3 if label == "base_exception" else 4, polls)
                if label == "ordinary_exception":
                    self.assertEqual("provider_failed", raised.exception.reason_code)
                elif label == "stop_reason":
                    self.assertEqual("execution_deadline_exceeded", raised.exception.reason_code)
                else:
                    self.assertIs(first, raised.exception)

    def test_linux_cancel_send_failure_preserves_the_first_control_outcome(self) -> None:
        class StopNow(BaseException):
            pass

        broker_key = b"p" * 32
        broker_nonce_bytes = b"q" * 32
        broker_nonce = broker_nonce_bytes.hex()
        ready = process_supervisor_module._encode_control(
            kind="ready",
            sequence=0,
            nonce=broker_nonce,
            payload={"worker_pid": 44_001, "worker_start_time": 112},
            key=broker_key,
        )

        class FakeSocket:
            def __init__(self) -> None:
                self.receives: list[bytes | BaseException] = [ready, BlockingIOError()]
                self.send_count = 0

            def send(self, payload: object) -> int:
                self.send_count += 1
                if self.send_count == 3:
                    raise OSError("cancel transport failed")
                return len(bytes(payload))

            def recv(self, _count: int) -> bytes:
                if not self.receives:
                    raise BlockingIOError()
                outcome = self.receives.pop(0)
                if isinstance(outcome, BaseException):
                    raise outcome
                return outcome

            def setblocking(self, _blocking: bool) -> None:
                return None

            def close(self) -> None:
                return None

        class FakeProcess:
            pid = 43_001

            def start(self) -> None:
                return None

            def is_alive(self) -> bool:
                return True

            def close(self) -> None:
                return None

        key = b"w" * 32
        frame = build_request_frame(_turn_request({"no": "execution"}), key=key, nonce="78" * 32)
        marker = StopNow("first base exception")
        cases: tuple[tuple[str, BaseException | str, type[BaseException]], ...] = (
            ("base_exception", marker, StopNow),
            ("deadline", "execution_deadline_exceeded", ProviderBoundaryStopped),
            ("ordinary", RuntimeError("first ordinary error"), ProviderBoundaryFailure),
        )
        for label, first, expected in cases:
            with self.subTest(case=label):
                parent = FakeSocket()
                context = mock.Mock()
                context.Process.return_value = FakeProcess()
                polls = 0

                def poll(first_outcome: BaseException | str = first) -> str | None:
                    nonlocal polls
                    polls += 1
                    if polls < 4:
                        return None
                    if isinstance(first_outcome, BaseException):
                        raise first_outcome
                    return first_outcome

                supervisor = process_supervisor_module.LinuxProcessSupervisor()
                with (
                    mock.patch.object(
                        process_supervisor_module.socket,
                        "socketpair",
                        return_value=(parent, FakeSocket()),
                    ),
                    mock.patch.object(
                        process_supervisor_module.os,
                        "urandom",
                        side_effect=(broker_key, broker_nonce_bytes),
                    ),
                    mock.patch.object(
                        process_supervisor_module.multiprocessing,
                        "get_context",
                        return_value=context,
                    ),
                    mock.patch.object(
                        process_supervisor_module,
                        "_retain_linux_identity",
                        side_effect=_fake_retained_identity,
                    ),
                    mock.patch.object(
                        process_supervisor_module,
                        "_cleanup_linux_broker_domain",
                        return_value=True,
                    ) as cleanup,
                    self.assertRaises(expected) as raised,
                ):
                    supervisor.execute(
                        frame,
                        worker_key=key,
                        boundary=ProviderBoundaryControl(poll),
                        turn_timeout_ms=1_000,
                    )
                self.assertEqual(4, polls)
                self.assertEqual(3, parent.send_count)
                cleanup.assert_called_once()
                if label == "base_exception":
                    self.assertIs(marker, raised.exception)
                elif label == "deadline":
                    self.assertEqual("execution_deadline_exceeded", raised.exception.reason_code)
                else:
                    self.assertEqual("provider_failed", raised.exception.reason_code)

    def test_linux_late_response_after_stop_is_rejected_with_proven_outcome(self) -> None:
        broker_key = b"p" * 32
        broker_nonce_bytes = b"q" * 32
        broker_nonce = broker_nonce_bytes.hex()
        ready = process_supervisor_module._encode_control(
            kind="ready",
            sequence=0,
            nonce=broker_nonce,
            payload={"worker_pid": 44_002, "worker_start_time": 112},
            key=broker_key,
        )
        domain_empty = process_supervisor_module._encode_control(
            kind="domain_empty",
            sequence=1,
            nonce=broker_nonce,
            payload={"status": "response", "response_base64": "UkVTVUxU"},
            key=broker_key,
        )

        class FakeSocket:
            def __init__(self) -> None:
                self.actions: list[bytes | BaseException] = [
                    ready,
                    BlockingIOError(),
                    domain_empty,
                    BlockingIOError(),
                ]
                self.sent = bytearray()

            def recv(self, _count: int) -> bytes:
                action = self.actions.pop(0)
                if isinstance(action, BaseException):
                    raise action
                return action

            def send(self, payload: object) -> int:
                raw = bytes(payload)
                self.sent.extend(raw)
                return len(raw)

            def setblocking(self, _blocking: bool) -> None:
                pass

            def close(self) -> None:
                pass

        class FakeChild:
            def close(self) -> None:
                pass

        class FakeProcess:
            pid = 44_001

            def __init__(self) -> None:
                self.alive = True

            def start(self) -> None:
                pass

            def join(self, _timeout: float) -> None:
                self.alive = False

            def is_alive(self) -> bool:
                return self.alive

        key = b"w" * 32
        frame = build_request_frame(_turn_request({"no": "execution"}), key=key, nonce="9a" * 32)
        cases: tuple[tuple[str, int | None, object, type[BaseException]], ...] = (
            (
                "timeout_before_domain_empty",
                None,
                (0.0, 0.0, 0.0, 0.0, 2.0),
                ProviderBoundaryFailure,
            ),
            (
                "timeout_after_domain_empty",
                None,
                (0.0, 0.0, 0.0, 0.0, 0.0, 2.0),
                ProviderBoundaryFailure,
            ),
            (
                "stop_before_domain_empty",
                4,
                0.0,
                ProviderBoundaryStopped,
            ),
            (
                "stop_after_domain_empty",
                5,
                0.0,
                ProviderBoundaryStopped,
            ),
        )
        for label, stop_at, monotonic, expected in cases:
            with self.subTest(case=label):
                parent = FakeSocket()
                process = FakeProcess()
                context = mock.Mock()
                context.Process.return_value = process
                supervisor = process_supervisor_module.LinuxProcessSupervisor()
                polls = 0

                def poll(stop_at: int | None = stop_at) -> str | None:
                    nonlocal polls
                    polls += 1
                    if stop_at is not None and polls >= stop_at:
                        return "execution_deadline_exceeded"
                    return None

                with (
                    mock.patch.object(
                        process_supervisor_module.socket,
                        "socketpair",
                        return_value=(parent, FakeChild()),
                    ),
                    mock.patch.object(
                        process_supervisor_module.os,
                        "urandom",
                        side_effect=(broker_key, broker_nonce_bytes),
                    ),
                    mock.patch.object(
                        process_supervisor_module.multiprocessing,
                        "get_context",
                        return_value=context,
                    ),
                    mock.patch.object(
                        process_supervisor_module,
                        "_retain_linux_identity",
                        side_effect=_fake_retained_identity,
                    ),
                    mock.patch.object(
                        process_supervisor_module,
                        "_cleanup_linux_broker_domain",
                        return_value=True,
                    ),
                    mock.patch.object(
                        process_supervisor_module.time,
                        "monotonic",
                        side_effect=monotonic if isinstance(monotonic, tuple) else None,
                        return_value=monotonic if isinstance(monotonic, float) else None,
                    ),
                    mock.patch.object(
                        process_supervisor_module._ControlReader,
                        "require_clean_eof",
                        return_value=None,
                    ),
                    self.assertRaises(expected) as raised,
                ):
                    supervisor.execute(
                        frame,
                        worker_key=key,
                        boundary=ProviderBoundaryControl(poll),
                        turn_timeout_ms=1_000,
                    )
                if expected is ProviderBoundaryFailure:
                    self.assertEqual("provider_failed", raised.exception.reason_code)
                else:
                    self.assertEqual("execution_deadline_exceeded", raised.exception.reason_code)
                self.assertNotEqual(b"", parent.sent)

    def test_crash_stderr_overflow_and_protocol_attacks_fail_closed_after_cleanup(self) -> None:
        cases = (
            "crash",
            "stderr",
            "output_overflow",
            "noncanonical",
            "duplicate_key",
            "wrong_mac",
            "wrong_nonce",
            "wrong_hash",
            "wrong_request_hash",
            "wrong_runtime",
            "trailing",
            "second_frame",
        )
        for action in cases:
            with self.subTest(action=action):
                supervisor = OneShotProviderSupervisor(turn_timeout_ms=1_000)
                with self.assertRaisesRegex(ProviderBoundaryFailure, "provider_failed"):
                    supervisor.turn(_turn_request(_case(action)), boundary=_control())
                self.assertEqual(1, supervisor.spawn_count)
                self.assertIsNone(supervisor.active_broker_pid)

    def test_result_protocol_rejects_nested_type_bound_and_collection_violations(self) -> None:
        cases = (
            _case("echo", completed=1),
            _case(
                "echo",
                usage={
                    "input_tokens": -1,
                    "output_tokens": 1,
                    "cached_input_tokens": 0,
                    "cost_minor_units": 0,
                    "currency": "USD",
                },
            ),
            _case("echo", tool_calls=[{"tool_id": "source.read"}]),
            _case(
                "echo",
                artifact_proposals=[{"private_payload": {}} for _ in range(65)],
            ),
        )
        for private_input in cases:
            with self.subTest(case=private_input):
                supervisor = OneShotProviderSupervisor(turn_timeout_ms=2_000)
                with self.assertRaisesRegex(ProviderBoundaryFailure, "provider_failed"):
                    supervisor.turn(_turn_request(private_input), boundary=_control())

    def test_double_fork_setsid_ignored_signal_and_inherited_pipe_are_all_reaped(self) -> None:
        supervisor = OneShotProviderSupervisor(turn_timeout_ms=2_000)
        result = supervisor.turn(
            _turn_request(_case("spawn_tree", include_worker_pid=True)),
            boundary=_control(),
        )
        pids = [result.private_output["worker_pid"], *result.private_output["descendant_pids"]]
        self.assertGreaterEqual(len(pids), 3)
        self.assertTrue(all(not Path(f"/proc/{pid}").exists() for pid in pids))

    def test_private_domain_cleanup_does_not_kill_unrelated_sibling(self) -> None:
        sibling = subprocess.Popen(
            (sys.executable, "-I", "-S", "-c", "import time; time.sleep(10)"),
            close_fds=True,
        )
        try:
            result = OneShotProviderSupervisor(turn_timeout_ms=2_000).turn(
                _turn_request(_case("spawn_tree")), boundary=_control()
            )
            self.assertTrue(result.completed)
            self.assertIsNone(sibling.poll())
        finally:
            sibling.kill()
            sibling.wait(timeout=2)

    def test_exact_duplicate_durable_evidence_spawns_zero_additional_child(self) -> None:
        activation, grant = _documents()
        request = replace(
            _request(activation, grant),
            private_input=_case("echo", payload={"stable": True}),
        )
        with tempfile.TemporaryDirectory() as temporary, AgentEventLog(temporary) as log:
            supervisor = OneShotProviderSupervisor(turn_timeout_ms=2_000)
            kernel = AgentExecutionKernel(
                provider=supervisor,
                broker=_kernel(supervisor)[0].broker,
                journal=log,
                clock=FakeClock(),
                cancellation=FakeCancellation(),
            )
            coordinator = AgentExecutionCoordinator(kernel=kernel, event_log=log)
            first = coordinator.execute(request)
            first_count = supervisor.spawn_count
            second = coordinator.execute(request)
            self.assertEqual("executed", first.disposition)
            self.assertEqual("existing_terminal", second.disposition)
            self.assertEqual(1, first_count)
            self.assertEqual(first_count, supervisor.spawn_count)

    def test_worker_cannot_bypass_parent_default_deny_tools_or_proposals(self) -> None:
        activation, grant = _documents()
        cases = (
            (
                _case(
                    "echo",
                    tool_calls=[{"tool_id": "source.read", "private_arguments": {"x": 1}}],
                ),
                "tool_not_authorized",
            ),
            (
                _case("echo", artifact_proposals=[{"private_payload": {"x": 1}}]),
                "artifact_capability_denied",
            ),
        )
        for private_input, reason in cases:
            with self.subTest(reason=reason):
                supervisor = OneShotProviderSupervisor(turn_timeout_ms=2_000)
                result = _kernel(supervisor)[0].execute(
                    replace(_request(activation, grant), private_input=private_input)
                )
                self.assertEqual("failed", result.outcome)
                self.assertEqual([reason], result.receipt["failure_codes"])

    def test_abrupt_parent_death_triggers_bounded_broker_tree_cleanup(self) -> None:
        scratch_before = set(Path("/tmp").glob("worldforge-worker-*"))
        script = r"""
import sys, threading, time
from worldforge.agent_harness import OneShotProviderSupervisor
from worldforge.agent_harness.ports import ProviderBoundaryControl, ProviderTurnRequest
def main():
    s = OneShotProviderSupervisor(turn_timeout_ms=30000)
    r = ProviderTurnRequest("execution_parent_death_01", 0, {
        "__worldforge_conformance__": {
            "action": "spawn_tree", "hold_milliseconds": 10000
        }
    }, ())
    t = threading.Thread(
        target=lambda: s.turn(r, boundary=ProviderBoundaryControl(lambda: None))
    )
    t.start()
    while s.active_broker_pid is None:
        time.sleep(0.001)
    print(s.active_broker_pid, flush=True)
    time.sleep(30)
if __name__ == "__main__":
    main()
"""
        parent = subprocess.Popen(
            (sys.executable, "-B", "-c", script),
            cwd=Path(__file__).resolve().parents[1],
            env={"PYTHONPATH": "src", "PYTHONDONTWRITEBYTECODE": "1"},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            close_fds=True,
        )
        assert parent.stdout is not None
        line = parent.stdout.readline().strip()
        broker_pid = int(line)
        deadline = time.monotonic() + 2
        descendants: set[int] = set()
        while time.monotonic() < deadline:
            descendants.update(_linux_descendants(broker_pid))
            if len(descendants) >= 3:
                break
            time.sleep(0.005)
        self.assertGreaterEqual(len(descendants), 3)
        parent.kill()
        parent.wait(timeout=2)
        parent.stdout.close()
        assert parent.stderr is not None
        parent.stderr.close()
        cleanup_deadline = time.monotonic() + 3
        while time.monotonic() < cleanup_deadline and (
            Path(f"/proc/{broker_pid}").exists()
            or any(Path(f"/proc/{pid}").exists() for pid in descendants)
        ):
            time.sleep(0.01)
        self.assertFalse(Path(f"/proc/{broker_pid}").exists())
        self.assertTrue(all(not Path(f"/proc/{pid}").exists() for pid in descendants))
        self.assertEqual(
            set(),
            set(Path("/tmp").glob("worldforge-worker-*")) - scratch_before,
        )

    def test_child_receives_empty_scratch_minimal_env_and_only_standard_descriptors(self) -> None:
        secret_name = "WORLD_FORGE_PRIVATE_TOKEN"
        os.environ[secret_name] = "MUST_NOT_CROSS"
        try:
            result = OneShotProviderSupervisor(turn_timeout_ms=2_000).turn(
                _turn_request(_case("audit_environment")), boundary=_control()
            )
        finally:
            os.environ.pop(secret_name, None)
        audit = result.private_output
        self.assertTrue(audit["scratch_empty"])
        self.assertEqual([0, 1, 2], audit["open_fds"])
        self.assertNotIn(secret_name, audit["environment_names"])
        self.assertNotIn("PATH", audit["environment_names"])
        self.assertNotIn("PYTHONPATH", audit["environment_names"])
        self.assertFalse(audit["worldforge_importable"])
        self.assertFalse(audit["isoworld_importable"])
        self.assertTrue(audit["dont_write_bytecode"])
        self.assertEqual("1", audit["telemetry"]["DO_NOT_TRACK"])

    def test_broker_loss_is_indeterminate_and_leaves_only_an_open_recoverable_prefix(self) -> None:
        activation, grant = _documents()
        with tempfile.TemporaryDirectory() as temporary:
            supervisor = OneShotProviderSupervisor(turn_timeout_ms=2_000)
            with AgentEventLog(temporary) as log:
                kernel = AgentExecutionKernel(
                    provider=supervisor,
                    broker=_kernel(supervisor)[0].broker,
                    journal=log,
                    clock=FakeClock(),
                    cancellation=FakeCancellation(),
                )

                killed = threading.Event()
                kill_errors: list[BaseException] = []

                def kill_broker() -> None:
                    deadline = time.monotonic() + 2
                    while time.monotonic() < deadline:
                        pid = supervisor.active_broker_pid
                        worker_pid = supervisor.active_worker_pid
                        if pid is not None and worker_pid is not None:
                            try:
                                os.kill(pid, signal.SIGKILL)
                            except BaseException as exc:
                                kill_errors.append(exc)
                            else:
                                killed.set()
                            return
                        time.sleep(0.001)

                killer = threading.Thread(target=kill_broker)
                killer.start()
                boundary_error: ProviderBoundaryIndeterminate | None = None
                execution_result = None
                try:
                    execution_result = kernel.execute(
                        replace(
                            _request(activation, grant),
                            private_input=_case("sleep", milliseconds=1_000),
                        )
                    )
                except ProviderBoundaryIndeterminate as exc:
                    boundary_error = exc
                killer.join(timeout=2)
                self.assertEqual([], kill_errors)
                self.assertTrue(killed.is_set())
                self.assertIsNotNone(
                    boundary_error,
                    None if execution_result is None else execution_result.receipt["failure_codes"],
                )
                replay = log.replay_records(str(activation["execution_id"]))
                self.assertEqual("open", replay.state)
                self.assertIsNone(replay.receipt_bytes)
                open_execution = log.list_open(limit=1)[0]
            with AgentEventLog.recovery(temporary) as recovery:
                recovered = recovery.mark_recovery_required(
                    open_execution.execution_id,
                    expected_sequence=open_execution.next_sequence,
                    expected_previous_hash=open_execution.head_hash,
                    expected_generation=open_execution.generation,
                )
                self.assertEqual("recovery_required", recovered.state)

    def test_indeterminate_post_spawn_exception_never_finalizes_a_durable_receipt(self) -> None:
        activation, grant = _documents()

        class IndeterminateProcessSupervisor:
            spawn_count = 1
            active_broker_pid = None
            active_worker_pid = None

            def execute(self, *_args: object, **_kwargs: object) -> object:
                raise ProviderBoundaryIndeterminate()

        provider = OneShotProviderSupervisor(turn_timeout_ms=1_000)
        provider._process_supervisor = IndeterminateProcessSupervisor()  # type: ignore[attr-defined]
        with tempfile.TemporaryDirectory() as temporary, AgentEventLog(temporary) as log:
            kernel = AgentExecutionKernel(
                provider=provider,
                broker=_kernel(provider)[0].broker,
                journal=log,
                clock=FakeClock(),
                cancellation=FakeCancellation(),
            )
            with self.assertRaisesRegex(
                ProviderBoundaryIndeterminate, "provider_boundary_indeterminate"
            ):
                kernel.execute(_request(activation, grant))
            replay = log.replay_records(str(activation["execution_id"]))
            self.assertEqual("open", replay.state)
            self.assertIsNone(replay.receipt_bytes)

    def test_broker_loss_kills_already_known_worker_descendants_best_effort(self) -> None:
        supervisor = OneShotProviderSupervisor(turn_timeout_ms=5_000)
        killed = threading.Event()
        observed: set[int] = set()
        kill_errors: list[BaseException] = []

        def kill_broker_after_tree_exists() -> None:
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                broker_pid = supervisor.active_broker_pid
                worker_pid = supervisor.active_worker_pid
                if broker_pid is not None and worker_pid is not None:
                    descendants = _linux_descendants(worker_pid)
                    if len(descendants) >= 2:
                        observed.update({worker_pid, *descendants})
                        try:
                            os.kill(broker_pid, signal.SIGKILL)
                        except BaseException as exc:
                            kill_errors.append(exc)
                        else:
                            killed.set()
                        return
                time.sleep(0.005)

        killer = threading.Thread(target=kill_broker_after_tree_exists)
        killer.start()
        try:
            with self.assertRaisesRegex(
                ProviderBoundaryIndeterminate, "provider_boundary_indeterminate"
            ):
                supervisor.turn(
                    _turn_request(_case("spawn_tree", hold_milliseconds=10_000)),
                    boundary=_control(),
                )
            killer.join(timeout=3)
            self.assertTrue(killed.is_set())
            self.assertEqual([], kill_errors)
            self.assertGreaterEqual(len(observed), 3)
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline and any(
                Path(f"/proc/{pid}").exists() for pid in observed
            ):
                time.sleep(0.01)
            self.assertTrue(all(not Path(f"/proc/{pid}").exists() for pid in observed))
        finally:
            killer.join(timeout=1)
            for pid in observed:
                try:
                    os.kill(pid, signal.SIGKILL)
                except (ProcessLookupError, OSError):
                    pass

    def test_turn_timeout_before_ready_kills_and_proves_the_broker_domain_empty(
        self,
    ) -> None:
        global _NO_READY_DESCENDANT_PATH

        key = b"n" * 32
        frame = build_request_frame(_turn_request({"no": "execution"}), key=key, nonce="ef" * 32)
        supervisor = process_supervisor_module.LinuxProcessSupervisor()
        descendant_pid: int | None = None
        with tempfile.TemporaryDirectory() as directory:
            pid_path = Path(directory) / "descendant.pid"
            _NO_READY_DESCENDANT_PATH = str(pid_path)
            started = time.monotonic()
            try:
                with (
                    mock.patch.object(
                        process_supervisor_module,
                        "_linux_broker_process_entry",
                        _slow_no_ready_broker,
                    ),
                    mock.patch.object(
                        process_supervisor_module.multiprocessing,
                        "get_context",
                        return_value=multiprocessing.get_context("fork"),
                    ),
                ):
                    with self.assertRaisesRegex(ProviderBoundaryFailure, "provider_failed"):
                        supervisor.execute(
                            frame,
                            worker_key=key,
                            boundary=_control(),
                            turn_timeout_ms=30,
                        )
                self.assertLess(time.monotonic() - started, 0.2)
                self.assertTrue(pid_path.is_file())
                descendant_pid = int(pid_path.read_text(encoding="ascii"))
                deadline = time.monotonic() + 1
                while time.monotonic() < deadline and Path(f"/proc/{descendant_pid}").exists():
                    time.sleep(0.01)
                self.assertFalse(Path(f"/proc/{descendant_pid}").exists())
                self.assertIsNone(supervisor.active_broker_pid)
            finally:
                _NO_READY_DESCENDANT_PATH = None
                if descendant_pid is None and pid_path.is_file():
                    descendant_pid = int(pid_path.read_text(encoding="ascii"))
                if descendant_pid is not None:
                    try:
                        os.kill(descendant_pid, signal.SIGKILL)
                    except (ProcessLookupError, OSError):
                        pass

    def test_stop_after_spawn_before_ready_also_closes_the_unreleased_domain(self) -> None:
        global _NO_READY_DESCENDANT_PATH

        key = b"s" * 32
        frame = build_request_frame(_turn_request({"no": "execution"}), key=key, nonce="12" * 32)
        supervisor = process_supervisor_module.LinuxProcessSupervisor()
        descendant_pid: int | None = None
        polls = 0

        def stop_after_initial_preflight() -> str | None:
            nonlocal polls
            polls += 1
            if polls == 1 or _NO_READY_DESCENDANT_PATH is None:
                return None
            return "execution_cancelled" if Path(_NO_READY_DESCENDANT_PATH).is_file() else None

        with tempfile.TemporaryDirectory() as directory:
            pid_path = Path(directory) / "descendant.pid"
            _NO_READY_DESCENDANT_PATH = str(pid_path)
            try:
                with (
                    mock.patch.object(
                        process_supervisor_module,
                        "_linux_broker_process_entry",
                        _slow_no_ready_broker,
                    ),
                    mock.patch.object(
                        process_supervisor_module.multiprocessing,
                        "get_context",
                        return_value=multiprocessing.get_context("fork"),
                    ),
                ):
                    with self.assertRaisesRegex(ProviderBoundaryStopped, "execution_cancelled"):
                        supervisor.execute(
                            frame,
                            worker_key=key,
                            boundary=ProviderBoundaryControl(stop_after_initial_preflight),
                            turn_timeout_ms=1_000,
                        )
                self.assertGreaterEqual(polls, 2)
                self.assertTrue(pid_path.is_file())
                descendant_pid = int(pid_path.read_text(encoding="ascii"))
                deadline = time.monotonic() + 1
                while time.monotonic() < deadline and Path(f"/proc/{descendant_pid}").exists():
                    time.sleep(0.01)
                self.assertFalse(Path(f"/proc/{descendant_pid}").exists())
            finally:
                _NO_READY_DESCENDANT_PATH = None
                if descendant_pid is None and pid_path.is_file():
                    descendant_pid = int(pid_path.read_text(encoding="ascii"))
                if descendant_pid is not None:
                    try:
                        os.kill(descendant_pid, signal.SIGKILL)
                    except (ProcessLookupError, OSError):
                        pass

    def test_linux_spawn_and_identity_failures_cleanup_owned_resources_before_outcome(
        self,
    ) -> None:
        class StopNow(BaseException):
            pass

        class FakeSocket:
            def __init__(self, name: str, operations: list[str]) -> None:
                self.name = name
                self.operations = operations

            def close(self) -> None:
                self.operations.append(f"close:{self.name}")

        class FakeProcess:
            def __init__(
                self,
                operations: list[str],
                *,
                start_error: BaseException | None,
                stubborn: bool,
            ) -> None:
                self.operations = operations
                self.start_error = start_error
                self.stubborn = stubborn
                self.alive = True
                self.pid = 41_001

            def start(self) -> None:
                self.operations.append("start")
                if self.start_error is not None:
                    raise self.start_error

            def kill(self) -> None:
                self.operations.append("kill")
                if not self.stubborn:
                    self.alive = False

            def join(self, timeout: float) -> None:
                self.operations.append(f"join:{timeout}")

            def is_alive(self) -> bool:
                return self.alive

            def close(self) -> None:
                self.operations.append("close:broker")

        key = b"o" * 32
        frame = build_request_frame(_turn_request({"no": "execution"}), key=key, nonce="34" * 32)
        cases: tuple[tuple[str, BaseException, bool, bool, type[BaseException]], ...] = (
            (
                "start_exception",
                RuntimeError("start failed"),
                True,
                False,
                ProviderBoundaryFailure,
            ),
            (
                "start_base_exception",
                StopNow("start interrupted"),
                True,
                False,
                StopNow,
            ),
            (
                "identity_exception",
                RuntimeError("identity failed"),
                False,
                False,
                ProviderBoundaryFailure,
            ),
            (
                "identity_base_exception",
                StopNow("identity interrupted"),
                False,
                False,
                StopNow,
            ),
            (
                "identity_base_cleanup_failure",
                StopNow("identity interrupted"),
                False,
                True,
                StopNow,
            ),
        )
        for label, marker, fail_start, stubborn, expected in cases:
            with self.subTest(case=label):
                operations: list[str] = []
                parent = FakeSocket("parent", operations)
                child = FakeSocket("child", operations)
                process = FakeProcess(
                    operations,
                    start_error=marker if fail_start else None,
                    stubborn=stubborn,
                )
                context = mock.Mock()
                context.Process.return_value = process
                supervisor = process_supervisor_module.LinuxProcessSupervisor()
                identity = (
                    mock.Mock(side_effect=AssertionError("identity must not run"))
                    if fail_start
                    else mock.Mock(side_effect=marker)
                )

                def stop_unidentified(
                    _process: FakeProcess,
                    operations: list[str] = operations,
                    stubborn: bool = stubborn,
                ) -> bool:
                    operations.extend(("pidfd_kill", "join:0.5"))
                    if stubborn:
                        return False
                    _process.alive = False
                    _process.close()
                    return True

                with (
                    mock.patch.object(
                        process_supervisor_module.socket,
                        "socketpair",
                        return_value=(parent, child),
                    ),
                    mock.patch.object(
                        process_supervisor_module.multiprocessing,
                        "get_context",
                        return_value=context,
                    ),
                    mock.patch.object(
                        process_supervisor_module,
                        "_retain_linux_identity",
                        identity,
                    ),
                    mock.patch.object(
                        supervisor,
                        "_stop_unidentified_broker",
                        side_effect=stop_unidentified,
                    ),
                    self.assertRaises(expected) as raised,
                ):
                    supervisor.execute(
                        frame,
                        worker_key=key,
                        boundary=_control(),
                        turn_timeout_ms=1_000,
                    )
                if expected is StopNow:
                    self.assertIs(marker, raised.exception)
                expected_operations = ["start", "pidfd_kill", "join:0.5"]
                if not stubborn:
                    expected_operations.append("close:broker")
                expected_operations.extend(("close:parent", "close:child"))
                self.assertEqual(expected_operations, operations)
                self.assertIsNone(supervisor.active_broker_pid)

    def test_linux_post_spawn_identity_base_exception_reaps_real_broker(self) -> None:
        class StopNow(BaseException):
            pass

        marker = StopNow("identity interrupted")
        broker_pids: list[int] = []

        def interrupt_identity(pid: int) -> tuple[int, int, str] | None:
            broker_pids.append(pid)
            raise marker

        key = b"r" * 32
        frame = build_request_frame(_turn_request({"no": "execution"}), key=key, nonce="bc" * 32)
        supervisor = process_supervisor_module.LinuxProcessSupervisor()
        with (
            mock.patch.object(
                process_supervisor_module,
                "_proc_identity",
                side_effect=interrupt_identity,
            ),
            self.assertRaises(StopNow) as raised,
        ):
            supervisor.execute(
                frame,
                worker_key=key,
                boundary=_control(),
                turn_timeout_ms=1_000,
            )
        self.assertIs(marker, raised.exception)
        self.assertEqual(1, len(broker_pids))
        self.assertFalse(Path(f"/proc/{broker_pids[0]}").exists())
        self.assertIsNone(supervisor.active_broker_pid)

    def test_linux_child_socket_close_base_exception_cleans_started_broker(self) -> None:
        class StopNow(BaseException):
            pass

        marker = StopNow("child close interrupted")
        operations: list[str] = []

        class FakeSocket:
            def __init__(self, name: str, *, fail_once: bool = False) -> None:
                self.name = name
                self.fail_once = fail_once

            def close(self) -> None:
                operations.append(f"close:{self.name}")
                if self.fail_once:
                    self.fail_once = False
                    raise marker

        class FakeProcess:
            pid = 46_001

            def __init__(self) -> None:
                self.alive = True

            def start(self) -> None:
                operations.append("start")

            def kill(self) -> None:
                operations.append("kill")
                self.alive = False

            def join(self, timeout: float) -> None:
                operations.append(f"join:{timeout}")

            def is_alive(self) -> bool:
                return self.alive

            def close(self) -> None:
                operations.append("close:broker")

        parent = FakeSocket("parent")
        child = FakeSocket("child", fail_once=True)
        process = FakeProcess()
        context = mock.Mock()
        context.Process.return_value = process
        key = b"s" * 32
        frame = build_request_frame(_turn_request({"no": "execution"}), key=key, nonce="de" * 32)
        supervisor = process_supervisor_module.LinuxProcessSupervisor()
        with (
            mock.patch.object(
                process_supervisor_module.socket,
                "socketpair",
                return_value=(parent, child),
            ),
            mock.patch.object(
                process_supervisor_module.multiprocessing,
                "get_context",
                return_value=context,
            ),
            mock.patch.object(
                process_supervisor_module,
                "_retain_linux_identity",
                side_effect=_fake_retained_identity,
            ),
            mock.patch.object(
                process_supervisor_module,
                "_cleanup_linux_broker_domain",
                return_value=True,
            ) as cleanup,
            self.assertRaises(StopNow) as raised,
        ):
            supervisor.execute(
                frame,
                worker_key=key,
                boundary=_control(),
                turn_timeout_ms=1_000,
            )
        self.assertIs(marker, raised.exception)
        cleanup.assert_called_once()
        self.assertEqual(
            [
                "start",
                "close:child",
                "close:parent",
                "close:child",
                "close:broker",
            ],
            operations,
        )

    def test_fixed_runtime_identity_and_bootstrap_are_not_caller_injectable(self) -> None:
        expected = {
            "id": "worldforge_conformance_provider",
            "revision": 2,
            "content_hash": hashlib.sha256(
                worker_module.WORKER_BOOTSTRAP_TEMPLATE.encode("utf-8")
            ).hexdigest(),
        }
        mutable_source = worker_registry_module.__dict__.get("CONFORMANCE_RUNTIME")
        if type(mutable_source) is dict:
            saved_source = dict(mutable_source)
            mutable_source.clear()
            mutable_source.update(
                id="caller_selected_runtime",
                revision=2,
                content_hash="f" * 64,
            )
            try:
                self.assertEqual(expected, fixed_runtime_identity())
            finally:
                mutable_source.clear()
                mutable_source.update(saved_source)
        self.assertNotIn("CONFORMANCE_RUNTIME", worker_registry_module.__dict__)
        exposed = fixed_runtime_identity()
        exposed.clear()
        exposed.update(
            id="caller_selected_runtime",
            revision=2,
            content_hash="f" * 64,
        )
        self.assertEqual(expected, fixed_runtime_identity())
        with self.assertRaises(TypeError):
            fixed_runtime_identity(  # type: ignore[call-arg]
                type(
                    "CallerBinding",
                    (),
                    {
                        "identifier": "caller_selected_runtime",
                        "revision": 2,
                        "content_hash": "f" * 64,
                    },
                )()
            )
        self.assertIn(
            '"id": "worldforge_conformance_provider"',
            worker_module.WORKER_BOOTSTRAP_TEMPLATE,
        )
        self.assertNotIn(
            '"id": "worldforge.conformance.provider"',
            worker_module.WORKER_BOOTSTRAP_TEMPLATE,
        )
        supervisor = OneShotProviderSupervisor(turn_timeout_ms=2_000)
        with self.assertRaises(TypeError):
            OneShotProviderSupervisor(command=("/bin/sh",))  # type: ignore[call-arg]
        self.assertNotIn("command", supervisor.__dict__)

    def test_fixed_command_is_code_owned(self) -> None:
        command = fixed_worker_command()
        self.assertEqual(os.path.abspath(sys.executable), command[0])
        self.assertEqual(("-I", "-B", "-S", "-u", "-X", "utf8", "-c"), command[1:8])

    def test_linux_identity_reuse_and_fixed_point_exhaustion_are_indeterminate(self) -> None:
        identity = process_supervisor_module._ProcessIdentity(1234, 10, 91)
        with mock.patch.object(
            process_supervisor_module, "_proc_identity", return_value=(1, 11, "S")
        ):
            with self.assertRaises(ProviderBoundaryIndeterminate):
                process_supervisor_module._signal_identity(identity, signal.SIGSTOP)

        table = {2: (1, 10, "S")}
        with (
            mock.patch.object(process_supervisor_module, "_DOMAIN_FIXED_POINT_LIMIT", 1),
            mock.patch.object(process_supervisor_module, "_reap_children"),
            mock.patch.object(process_supervisor_module, "_process_table", return_value=table),
            mock.patch.object(process_supervisor_module, "_signal_identity", return_value=True),
        ):
            self.assertFalse(
                process_supervisor_module._prove_linux_domain_empty(broker_pid=1, tracked={2: 10})
            )

        class GoneBroker:
            def join(self, _timeout):
                return None

            def is_alive(self):
                return False

            def kill(self):
                raise AssertionError("an already missing broker must not need a fallback kill")

        with (
            mock.patch.object(process_supervisor_module, "_process_table", return_value={}),
            mock.patch.object(process_supervisor_module, "_proc_identity", return_value=None),
            mock.patch.object(process_supervisor_module, "_signal_identity", return_value=True),
        ):
            self.assertFalse(
                process_supervisor_module._cleanup_linux_broker_domain(
                    broker=GoneBroker(),
                    broker_identity=identity,
                    tracked={},
                )
            )

        with (
            mock.patch.object(
                process_supervisor_module,
                "_process_table",
                return_value={identity.pid: (1, identity.start_time, "S")},
            ),
            mock.patch.object(process_supervisor_module, "_proc_identity", return_value=None),
            mock.patch.object(
                process_supervisor_module,
                "_signal_identity",
                return_value=True,
            ),
        ):
            self.assertFalse(
                process_supervisor_module._cleanup_linux_broker_domain(
                    broker=GoneBroker(),
                    broker_identity=identity,
                    tracked={},
                )
            )

    def test_linux_pidfd_signals_are_bound_and_never_fall_back_to_pid_kill(self) -> None:
        expected = (1, 10, "S")
        sent: list[tuple[int, int]] = []
        closed: list[int] = []
        with (
            mock.patch.object(process_supervisor_module.os, "pidfd_open", return_value=91),
            mock.patch.object(process_supervisor_module, "_proc_identity", return_value=expected),
            mock.patch.object(
                process_supervisor_module.signal,
                "pidfd_send_signal",
                side_effect=lambda descriptor, signum, *_args: sent.append((descriptor, signum)),
            ),
            mock.patch.object(
                process_supervisor_module.os,
                "kill",
                side_effect=AssertionError("PID signaling must never be a containment fallback"),
            ),
            mock.patch.object(
                process_supervisor_module.os,
                "close",
                side_effect=lambda descriptor: closed.append(descriptor),
            ),
        ):
            retained = process_supervisor_module._retain_linux_identity(1234, 10)
            self.assertIsNotNone(retained)
            assert retained is not None
            self.assertTrue(process_supervisor_module._signal_identity(retained, signal.SIGSTOP))
            self.assertTrue(process_supervisor_module._close_linux_identity(retained))
        self.assertEqual([(91, signal.SIGSTOP)], sent)
        self.assertEqual([91], closed)

        reused = process_supervisor_module._ProcessIdentity(1234, 10, 92)
        with (
            mock.patch.object(
                process_supervisor_module,
                "_proc_identity",
                side_effect=((1, 10, "S"), (1, 11, "S")),
            ),
            mock.patch.object(
                process_supervisor_module.signal, "pidfd_send_signal", return_value=None
            ) as pidfd_signal,
            mock.patch.object(
                process_supervisor_module.os,
                "kill",
                side_effect=AssertionError("a reused PID must not be signaled"),
            ),
            self.assertRaisesRegex(
                ProviderBoundaryIndeterminate, "provider_boundary_indeterminate"
            ),
        ):
            process_supervisor_module._signal_identity(reused, signal.SIGKILL)
        pidfd_signal.assert_called_once_with(92, signal.SIGKILL, None, 0)

        for failure in (
            mock.patch.object(
                process_supervisor_module.os,
                "pidfd_open",
                side_effect=OSError("pidfd unavailable"),
            ),
            mock.patch.object(
                process_supervisor_module.signal,
                "pidfd_send_signal",
                side_effect=OSError("pidfd signal failed"),
            ),
        ):
            with self.subTest(failure=failure.attribute):
                with (
                    failure,
                    mock.patch.object(
                        process_supervisor_module.os,
                        "kill",
                        side_effect=AssertionError("racy fallback forbidden"),
                    ),
                ):
                    with self.assertRaisesRegex(
                        ProviderBoundaryIndeterminate, "provider_boundary_indeterminate"
                    ):
                        if failure.attribute == "pidfd_open":
                            process_supervisor_module._retain_linux_identity(1234, 10)
                        else:
                            with mock.patch.object(
                                process_supervisor_module,
                                "_proc_identity",
                                return_value=expected,
                            ):
                                process_supervisor_module._signal_identity(
                                    process_supervisor_module._ProcessIdentity(1234, 10, 93),
                                    signal.SIGSTOP,
                                )

    def test_linux_pidfd_close_base_exception_is_total_and_never_double_closes(self) -> None:
        class CloseNow(BaseException):
            pass

        closed: list[int] = []
        retained = process_supervisor_module._ProcessIdentity(1_234, 10, 94)

        def interrupt_close(descriptor: int) -> None:
            closed.append(descriptor)
            raise CloseNow("close interrupted")

        with mock.patch.object(
            process_supervisor_module.os,
            "close",
            side_effect=interrupt_close,
        ):
            self.assertFalse(process_supervisor_module._close_linux_identity(retained))
            self.assertTrue(retained.pidfd_close_attempted)
            self.assertIsNone(retained.pidfd)
            self.assertFalse(process_supervisor_module._close_linux_identity(retained))
        self.assertEqual([94], closed)

    def test_linux_pidfd_signal_closes_owned_handle_without_replacing_base_exception(
        self,
    ) -> None:
        class StopNow(BaseException):
            pass

        class CloseNow(BaseException):
            pass

        marker = StopNow("identity inspection interrupted")
        retained = process_supervisor_module._ProcessIdentity(1_234, 10, 95)
        closed: list[int] = []
        with (
            mock.patch.object(
                process_supervisor_module,
                "_retain_linux_identity",
                return_value=retained,
            ),
            mock.patch.object(
                process_supervisor_module,
                "_proc_identity",
                side_effect=marker,
            ),
            mock.patch.object(
                process_supervisor_module.os,
                "close",
                side_effect=lambda descriptor: closed.append(descriptor),
            ),
            self.assertRaises(StopNow) as raised,
        ):
            process_supervisor_module._signal_identity(
                process_supervisor_module._ProcessIdentity(1_234, 10),
                signal.SIGSTOP,
            )
        self.assertIs(marker, raised.exception)
        self.assertEqual([95], closed)

        signal_marker = StopNow("pidfd signaling interrupted")
        retained = process_supervisor_module._ProcessIdentity(1_234, 10, 96)
        close_calls: list[int] = []

        def interrupt_close(descriptor: int) -> None:
            close_calls.append(descriptor)
            raise CloseNow("pidfd close interrupted")

        with (
            mock.patch.object(
                process_supervisor_module,
                "_retain_linux_identity",
                return_value=retained,
            ),
            mock.patch.object(
                process_supervisor_module,
                "_proc_identity",
                return_value=(1, 10, "S"),
            ),
            mock.patch.object(
                process_supervisor_module.signal,
                "pidfd_send_signal",
                side_effect=signal_marker,
            ),
            mock.patch.object(
                process_supervisor_module.os,
                "close",
                side_effect=interrupt_close,
            ),
            self.assertRaises(StopNow) as raised,
        ):
            process_supervisor_module._signal_identity(
                process_supervisor_module._ProcessIdentity(1_234, 10),
                signal.SIGKILL,
            )
        self.assertIs(signal_marker, raised.exception)
        self.assertEqual([96], close_calls)
        self.assertTrue(retained.pidfd_close_quarantined)

    def test_linux_pidfd_cleanup_kills_only_the_retained_real_process(self) -> None:
        before_fds = set(os.listdir("/proc/self/fd"))
        target = subprocess.Popen(
            (sys.executable, "-I", "-B", "-S", "-c", "import time; time.sleep(30)"),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
        )
        sibling = subprocess.Popen(
            (sys.executable, "-I", "-B", "-S", "-c", "import time; time.sleep(30)"),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
        )
        retained = None
        try:
            entry = process_supervisor_module._proc_identity(target.pid)
            self.assertIsNotNone(entry)
            assert entry is not None
            retained = process_supervisor_module._retain_linux_identity(target.pid, entry[1])
            self.assertIsNotNone(retained)
            assert retained is not None
            self.assertTrue(process_supervisor_module._signal_identity(retained, signal.SIGSTOP))
            deadline = time.monotonic() + 1
            while time.monotonic() < deadline:
                stopped = process_supervisor_module._proc_identity(target.pid)
                if stopped is not None and stopped[2] in {"T", "t"}:
                    break
                time.sleep(0.002)
            self.assertIsNotNone(stopped)
            assert stopped is not None
            self.assertIn(stopped[2], {"T", "t"})
            self.assertTrue(process_supervisor_module._signal_identity(retained, signal.SIGKILL))
            target.wait(timeout=2)
            self.assertIsNone(sibling.poll())
        finally:
            if retained is not None:
                self.assertTrue(process_supervisor_module._close_linux_identity(retained))
            if target.poll() is None:
                target.kill()
                target.wait(timeout=2)
            if sibling.poll() is None:
                sibling.kill()
                sibling.wait(timeout=2)
        self.assertEqual(before_fds, set(os.listdir("/proc/self/fd")))

    def test_linux_supervisor_retains_and_closes_broker_and_worker_pidfds(self) -> None:
        real_pidfd_open = os.pidfd_open
        opened: list[int] = []

        def observe_open(pid: int, flags: int = 0) -> int:
            descriptor = real_pidfd_open(pid, flags)
            opened.append(descriptor)
            return descriptor

        with mock.patch.object(
            process_supervisor_module.os,
            "pidfd_open",
            side_effect=observe_open,
        ):
            result = OneShotProviderSupervisor(turn_timeout_ms=2_000).turn(
                _turn_request(_case("echo", payload="retained-pidfds")),
                boundary=_control(),
            )
        self.assertEqual("retained-pidfds", result.private_output["payload"])
        self.assertGreaterEqual(len(opened), 2)
        for descriptor in opened:
            with self.subTest(descriptor=descriptor):
                with self.assertRaises(OSError):
                    os.fstat(descriptor)

    def test_linux_supervisor_rejects_missing_pidfd_api_before_spawn(self) -> None:
        with mock.patch.object(process_supervisor_module.os, "pidfd_open", None):
            with self.assertRaisesRegex(
                ProviderBoundaryUnsupported, "worker_containment_unavailable"
            ):
                process_supervisor_module.LinuxProcessSupervisor()

    def test_linux_cleanup_observes_sigstop_before_accepting_a_frozen_domain(self) -> None:
        identity = process_supervisor_module._ProcessIdentity(1_234, 10)
        child = 1_235
        running_table = {
            identity.pid: (1, identity.start_time, "S"),
            child: (identity.pid, 11, "S"),
        }

        class Broker:
            def join(self, _timeout):
                return None

            def is_alive(self):
                return False

            def kill(self):
                raise AssertionError("fallback kill must not be needed")

        with (
            mock.patch.object(process_supervisor_module, "_DOMAIN_FIXED_POINT_LIMIT", 3),
            mock.patch.object(
                process_supervisor_module,
                "_process_table",
                return_value=running_table,
            ),
            mock.patch.object(
                process_supervisor_module,
                "_proc_identity",
                return_value=None,
            ),
            mock.patch.object(
                process_supervisor_module,
                "_signal_identity",
                return_value=True,
            ),
        ):
            self.assertFalse(
                process_supervisor_module._cleanup_linux_broker_domain(
                    broker=Broker(),
                    broker_identity=identity,
                    tracked={},
                )
            )

    def test_linux_pidfd_cleanup_failure_never_falls_back_to_process_kill(self) -> None:
        identity = process_supervisor_module._ProcessIdentity(1_234, 10, 91)
        fallback_kills: list[str] = []

        class Broker:
            def join(self, _timeout: float) -> None:
                return None

            def is_alive(self) -> bool:
                return True

            def kill(self) -> None:
                fallback_kills.append("kill")

        table = {identity.pid: (1, identity.start_time, "T")}
        with (
            mock.patch.object(process_supervisor_module, "_DOMAIN_FIXED_POINT_LIMIT", 2),
            mock.patch.object(process_supervisor_module, "_process_table", return_value=table),
            mock.patch.object(
                process_supervisor_module,
                "_observe_linux_identities_stopped",
                return_value=True,
            ),
            mock.patch.object(
                process_supervisor_module,
                "_signal_identity",
                return_value=False,
            ),
        ):
            self.assertFalse(
                process_supervisor_module._cleanup_linux_broker_domain(
                    broker=Broker(),
                    broker_identity=identity,
                    tracked={},
                )
            )
        self.assertEqual([], fallback_kills)

    def test_linux_confirmed_freeze_rescans_and_kills_a_late_descendant(self) -> None:
        broker_pid = 1_300
        child = 1_301
        late_child = 1_302
        child_running = {child: (broker_pid, 20, "S")}
        late_running = {
            child: (broker_pid, 20, "T"),
            late_child: (child, 30, "S"),
        }
        all_stopped = {
            child: (broker_pid, 20, "T"),
            late_child: (child, 30, "T"),
        }
        tables = iter(
            (
                child_running,
                late_running,
                late_running,
                late_running,
                all_stopped,
                all_stopped,
                {},
                {},
            )
        )
        signals: list[tuple[int, int]] = []

        def signal_identity(identity, signum: int) -> bool:
            signals.append((identity.pid, signum))
            return True

        tracked = {child: 20}
        with (
            mock.patch.object(process_supervisor_module, "_reap_children"),
            mock.patch.object(
                process_supervisor_module,
                "_process_table",
                side_effect=lambda: next(tables),
            ),
            mock.patch.object(
                process_supervisor_module,
                "_signal_identity",
                side_effect=signal_identity,
            ),
        ):
            self.assertTrue(
                process_supervisor_module._prove_linux_domain_empty(
                    broker_pid=broker_pid,
                    tracked=tracked,
                )
            )
        self.assertEqual({child: 20, late_child: 30}, tracked)
        self.assertIn((late_child, signal.SIGSTOP), signals)
        self.assertIn((late_child, signal.SIGKILL), signals)
        self.assertLess(
            signals.index((late_child, signal.SIGSTOP)),
            signals.index((late_child, signal.SIGKILL)),
        )

    def test_linux_setup_cleanup_cannot_replace_the_original_base_exception(self) -> None:
        class StopNow(BaseException):
            pass

        class CleanupNow(BaseException):
            pass

        class FakeProcess:
            pid = 41_002

            def start(self) -> None:
                return None

            def close(self) -> None:
                return None

        key = b"s" * 32
        frame = build_request_frame(_turn_request({"no": "execution"}), key=key, nonce="ef" * 32)
        cases: tuple[tuple[BaseException, object, type[BaseException]], ...] = (
            (StopNow("setup interrupted"), CleanupNow("cleanup interrupted"), StopNow),
            (
                RuntimeError("setup failed after cleanup raised"),
                CleanupNow("cleanup interrupted"),
                ProviderBoundaryIndeterminate,
            ),
            (
                RuntimeError("setup failed after cleanup returned false"),
                False,
                ProviderBoundaryIndeterminate,
            ),
            (
                RuntimeError("setup failed after cleanup proved empty"),
                True,
                ProviderBoundaryFailure,
            ),
        )
        for original, cleanup_outcome, expected in cases:
            with self.subTest(original=type(original).__name__):

                class FakeSocket:
                    def __init__(self, *, error: BaseException | None = None) -> None:
                        self.error = error

                    def close(self) -> None:
                        if self.error is not None:
                            error = self.error
                            self.error = None
                            raise error

                context = mock.Mock()
                context.Process.return_value = FakeProcess()
                cleanup = mock.Mock()
                if isinstance(cleanup_outcome, BaseException):
                    cleanup.side_effect = cleanup_outcome
                else:
                    cleanup.return_value = cleanup_outcome
                supervisor = process_supervisor_module.LinuxProcessSupervisor()
                with (
                    mock.patch.object(
                        process_supervisor_module.socket,
                        "socketpair",
                        return_value=(FakeSocket(), FakeSocket(error=original)),
                    ),
                    mock.patch.object(
                        process_supervisor_module.multiprocessing,
                        "get_context",
                        return_value=context,
                    ),
                    mock.patch.object(
                        process_supervisor_module,
                        "_retain_linux_identity",
                        side_effect=_fake_retained_identity,
                    ),
                    mock.patch.object(
                        process_supervisor_module,
                        "_cleanup_linux_broker_domain",
                        cleanup,
                    ),
                    self.assertRaises(expected) as raised,
                ):
                    supervisor.execute(
                        frame,
                        worker_key=key,
                        boundary=_control(),
                        turn_timeout_ms=1_000,
                    )
                if expected is StopNow:
                    self.assertIs(original, raised.exception)
                elif expected is ProviderBoundaryFailure:
                    self.assertEqual("provider_failed", raised.exception.reason_code)
                else:
                    self.assertEqual(
                        "provider_boundary_indeterminate", raised.exception.reason_code
                    )

    def test_linux_cleanup_base_exception_preserves_running_and_final_outcomes(self) -> None:
        class StopNow(BaseException):
            pass

        class CleanupNow(BaseException):
            pass

        class FakeSocket:
            def __init__(self, receive: BaseException | None = None) -> None:
                self.receive = receive

            def send(self, payload: object) -> int:
                return len(bytes(payload))

            def recv(self, _count: int) -> bytes:
                if self.receive is not None:
                    raise self.receive
                raise BlockingIOError()

            def setblocking(self, _blocking: bool) -> None:
                return None

            def close(self) -> None:
                return None

        class FakeProcess:
            pid = 41_003

            def start(self) -> None:
                return None

            def close(self) -> None:
                return None

            def is_alive(self) -> bool:
                return True

        key = b"t" * 32
        frame = build_request_frame(_turn_request({"no": "execution"}), key=key, nonce="fa" * 32)
        running_base = StopNow("running parent interruption")
        final_base = StopNow("final reader interruption")
        cases: tuple[
            tuple[str, BaseException | str, BaseException | None, type[BaseException]], ...
        ] = (
            ("running_base", running_base, None, StopNow),
            (
                "running_ordinary",
                RuntimeError("ordinary callback"),
                None,
                ProviderBoundaryIndeterminate,
            ),
            (
                "running_stop",
                "execution_deadline_exceeded",
                None,
                ProviderBoundaryIndeterminate,
            ),
            ("final_base", StopNow("unused"), final_base, StopNow),
            (
                "final_ordinary",
                StopNow("unused"),
                RuntimeError("final reader failure"),
                ProviderBoundaryIndeterminate,
            ),
        )
        for label, outcome, receive, expected in cases:
            with self.subTest(case=label):
                parent = FakeSocket(receive)
                context = mock.Mock()
                context.Process.return_value = FakeProcess()
                polls = 0

                def poll(
                    outcome: BaseException | str = outcome,
                    receive: BaseException | None = receive,
                ) -> str | None:
                    nonlocal polls
                    polls += 1
                    if receive is not None or polls == 1:
                        return None
                    if isinstance(outcome, BaseException):
                        raise outcome
                    return outcome

                cleanup = mock.Mock(side_effect=CleanupNow("cleanup interrupted"))
                supervisor = process_supervisor_module.LinuxProcessSupervisor()
                with (
                    mock.patch.object(
                        process_supervisor_module.socket,
                        "socketpair",
                        return_value=(parent, FakeSocket()),
                    ),
                    mock.patch.object(
                        process_supervisor_module.multiprocessing,
                        "get_context",
                        return_value=context,
                    ),
                    mock.patch.object(
                        process_supervisor_module,
                        "_retain_linux_identity",
                        side_effect=_fake_retained_identity,
                    ),
                    mock.patch.object(
                        process_supervisor_module,
                        "_cleanup_linux_broker_domain",
                        cleanup,
                    ),
                    self.assertRaises(expected) as raised,
                ):
                    supervisor.execute(
                        frame,
                        worker_key=key,
                        boundary=ProviderBoundaryControl(poll),
                        turn_timeout_ms=1_000,
                    )
                cleanup.assert_called_once()
                if label == "running_base":
                    self.assertIs(running_base, raised.exception)
                elif label == "final_base":
                    self.assertIs(final_base, raised.exception)
                elif label in {"running_ordinary", "running_stop", "final_ordinary"}:
                    self.assertEqual(
                        "provider_boundary_indeterminate", raised.exception.reason_code
                    )

    def test_unsupported_os_rejects_supervisor_before_any_journal_can_begin(self) -> None:
        with mock.patch("worldforge.agent_harness.supervisor.sys.platform", "darwin"):
            with self.assertRaisesRegex(
                ProviderBoundaryUnsupported, "worker_containment_unavailable"
            ):
                OneShotProviderSupervisor()


class ProviderWorkerPlatformBoundaryTests(unittest.TestCase):
    def test_windows_rejects_before_journal_or_process_authority(self) -> None:
        forbidden = AssertionError("unsupported host crossed the containment preflight")
        with (
            mock.patch(
                "worldforge.agent_harness.supervisor.sys.platform",
                "win32",
            ),
            mock.patch.object(
                AgentEventLog,
                "begin_execution",
                side_effect=forbidden,
            ) as begin,
            mock.patch.object(
                AgentEventLog,
                "finalize",
                side_effect=forbidden,
            ) as finalize,
            mock.patch.object(
                process_supervisor_module.multiprocessing,
                "get_context",
                side_effect=forbidden,
            ) as broker,
            mock.patch.object(
                process_supervisor_module.ctypes,
                "WinDLL",
                create=True,
                side_effect=forbidden,
            ) as job_api,
            mock.patch.object(
                process_supervisor_module.subprocess,
                "Popen",
                side_effect=forbidden,
            ) as process,
            mock.patch(
                "worldforge.agent_harness.supervisor.build_request_frame",
                side_effect=forbidden,
            ) as provider_action,
            self.assertRaisesRegex(
                ProviderBoundaryUnsupported,
                "worker_containment_unavailable",
            ),
        ):
            OneShotProviderSupervisor()
        begin.assert_not_called()
        finalize.assert_not_called()
        broker.assert_not_called()
        job_api.assert_not_called()
        process.assert_not_called()
        provider_action.assert_not_called()


class WorkerRequestDecoderHardeningTests(unittest.TestCase):
    @unittest.skipIf(os.name == "nt", "POSIX descriptor seam is Linux-only")
    def test_worker_rejects_all_unexpected_process_arguments_before_action(self) -> None:
        key = b"g" * 32
        nonce = "bc" * 32
        request_frame = build_request_frame(
            _turn_request(_case("echo", payload="must-not-run")),
            key=key,
            nonce=nonce,
        )
        gate_read, gate_write = os.pipe()
        try:
            os.write(gate_write, b"\x01")
            os.close(gate_write)
            gate_write = -1
            cases = (
                (f"fd:{gate_read}", (gate_read,)),
                ("handle:99", ()),
            )
            for argument, pass_fds in cases:
                with self.subTest(argument=argument):
                    completed = subprocess.run(
                        (*fixed_worker_command(), argument),
                        input=key + request_frame,
                        capture_output=True,
                        pass_fds=pass_fds,
                        timeout=2,
                        check=False,
                    )
                    self.assertEqual(70, completed.returncode)
                    self.assertEqual(b"", completed.stdout)
                    self.assertEqual(b"", completed.stderr)
        finally:
            if gate_read >= 0:
                os.close(gate_read)
            if gate_write >= 0:
                os.close(gate_write)

    def test_worker_rejects_exact_authenticated_request_shape_before_action(self) -> None:
        key = b"x" * 32
        nonce = "ab" * 32
        request = _turn_request(_case("crash"))
        valid = build_request_frame(request, key=key, nonce=nonce)

        deep: object = "leaf"
        for _ in range(65):
            deep = {"nested": deep}

        def mutate_request(
            document: dict[str, object],
            mutation: object,
        ) -> None:
            request_payload = document["request"]
            assert type(request_payload) is dict
            field, value = mutation  # type: ignore[misc]
            if value is _DELETE:
                del request_payload[field]
            elif field == "extra":
                request_payload["unexpected"] = value
            else:
                request_payload[field] = value
            document["request_hash"] = hashlib.sha256(
                json.dumps(
                    request_payload,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                    allow_nan=False,
                ).encode("utf-8")
            ).hexdigest()

        cases: tuple[tuple[str, object], ...] = (
            ("uppercase_nonce", ("nonce", nonce.upper())),
            ("bool_nonce", ("nonce", True)),
            ("bool_execution_id", ("request", ("execution_id", True))),
            ("invalid_execution_id", ("request", ("execution_id", "INVALID"))),
            ("bool_turn", ("request", ("turn_index", True))),
            ("turn_out_of_bounds", ("request", ("turn_index", 65))),
            ("history_wrong_type", ("request", ("history", {}))),
            ("history_too_large", ("request", ("history", [{}] * 257))),
            ("private_depth", ("request", ("private_input", deep))),
            ("request_extra", ("request", ("extra", "value"))),
            ("request_missing", ("request", ("history", _DELETE))),
        )
        for label, mutation in cases:
            with self.subTest(case=label):
                document = _frame_document(valid)
                target, value = mutation  # type: ignore[misc]
                if target == "request":
                    mutate_request(document, value)
                else:
                    document[target] = value
                malformed = _authenticated_frame(document, key)
                completed = subprocess.run(
                    fixed_worker_command(),
                    input=key + malformed,
                    capture_output=True,
                    timeout=2,
                    check=False,
                )
                self.assertEqual(70, completed.returncode)
                self.assertEqual(b"", completed.stdout)
                self.assertEqual(b"", completed.stderr)

    @unittest.skipUnless(sys.platform.startswith("linux"), "/proc FD audit is Linux-only")
    def test_worker_fd_audit_observes_inherited_descriptor_above_63(self) -> None:
        descriptors: list[int] = []
        try:
            while not descriptors or descriptors[-1] < 96:
                read_fd, write_fd = os.pipe()
                descriptors.extend((read_fd, write_fd))
            inherited = descriptors[-1]
            key = b"f" * 32
            nonce = "cd" * 32
            request_frame = build_request_frame(
                _turn_request(_case("audit_environment")),
                key=key,
                nonce=nonce,
            )
            completed = subprocess.run(
                fixed_worker_command(),
                input=key + request_frame,
                pass_fds=(inherited,),
                capture_output=True,
                timeout=2,
                check=False,
            )
            self.assertEqual(0, completed.returncode)
            request_hash = _frame_document(request_frame)["request_hash"]
            assert type(request_hash) is str
            result = parse_result_frame(
                completed.stdout,
                key=key,
                nonce=nonce,
                request_hash=request_hash,
            )
            self.assertIn(inherited, result.private_output["open_fds"])
        finally:
            for descriptor in descriptors:
                try:
                    os.close(descriptor)
                except OSError:
                    pass

    def test_runtime_hash_is_pinned_to_the_actual_bootstrap_template(self) -> None:
        material = worker_module.WORKER_BOOTSTRAP_TEMPLATE.encode("utf-8")
        expected = hashlib.sha256(material).hexdigest()
        self.assertEqual(expected, fixed_runtime_identity()["content_hash"])
        self.assertNotIn(worker_module.RUNTIME_CONTENT_HASH_TOKEN, worker_module.WORKER_BOOTSTRAP)
        self.assertIn(expected, worker_module.WORKER_BOOTSTRAP)


_DELETE = object()


class BrokerControlProtocolTests(unittest.TestCase):
    @staticmethod
    def _body(frame: bytes) -> bytes:
        size = int.from_bytes(frame[:4], "big")
        return frame[4 : 4 + size]

    @staticmethod
    def _reauthenticate(document: dict[str, object], key: bytes) -> bytes:
        body = {name: value for name, value in document.items() if name != "mac"}
        document["mac"] = hmac.new(
            key,
            process_supervisor_module._canonical(body),
            hashlib.sha256,
        ).hexdigest()
        return process_supervisor_module._canonical(document)

    def test_control_decoder_requires_exact_builtin_types_and_kind_payload(self) -> None:
        key = b"c" * 32
        nonce = "12" * 32
        frame = process_supervisor_module._encode_control(
            kind="cancel",
            sequence=1,
            nonce=nonce,
            payload={},
            key=key,
        )
        valid = json.loads(self._body(frame).decode("utf-8"))
        mutations = (
            ("bool_version", lambda item: item.__setitem__("format_version", True)),
            ("bool_sequence", lambda item: item.__setitem__("sequence", True)),
            ("unexpected_cancel_payload", lambda item: item.__setitem__("payload", {"x": 1})),
        )
        for label, mutate in mutations:
            with self.subTest(case=label):
                document = json.loads(json.dumps(valid))
                mutate(document)
                with self.assertRaises(ProviderBoundaryIndeterminate):
                    process_supervisor_module._decode_control(
                        self._reauthenticate(document, key),
                        key=key,
                        nonce=nonce,
                        kind="cancel",
                        sequence=1,
                    )

        ready = process_supervisor_module._encode_control(
            kind="ready",
            sequence=0,
            nonce=nonce,
            payload={"worker_pid": 100, "worker_start_time": 200},
            key=key,
        )
        for field, value in (("worker_pid", True), ("worker_start_time", 0)):
            with self.subTest(ready_field=field):
                document = json.loads(self._body(ready).decode("utf-8"))
                document["payload"][field] = value
                with self.assertRaises(ProviderBoundaryIndeterminate):
                    process_supervisor_module._decode_control(
                        self._reauthenticate(document, key),
                        key=key,
                        nonce=nonce,
                        kind="ready",
                        sequence=0,
                    )

    def test_control_reader_requires_eof_after_one_terminal_frame(self) -> None:
        key = b"e" * 32
        nonce = "34" * 32
        terminal = process_supervisor_module._encode_control(
            kind="domain_empty",
            sequence=1,
            nonce=nonce,
            payload={"status": "provider_failed"},
            key=key,
        )
        left, right = socket.socketpair()
        try:
            left.setblocking(False)
            reader = process_supervisor_module._ControlReader(left)
            right.sendall(terminal + terminal)
            right.close()
            self.assertEqual(self._body(terminal), reader.poll())
            with self.assertRaises(ProviderBoundaryIndeterminate):
                reader.require_clean_eof(timeout_seconds=0.2)
        finally:
            left.close()
            try:
                right.close()
            except OSError:
                pass


@unittest.skipUnless(sys.platform.startswith("linux"), "real containment probe is Linux-only")
class LinuxOwnershipRegressionTests(unittest.TestCase):
    def test_linux_private_timeout_starts_before_parent_scratch_setup(self) -> None:
        operations: list[str] = []

        def now() -> float:
            operations.append("clock")
            return 0.0

        def fail_scratch(*_args, **_kwargs) -> str:
            operations.append("scratch")
            raise RuntimeError("scratch setup failed")

        supervisor = process_supervisor_module.LinuxProcessSupervisor()
        with (
            mock.patch.object(process_supervisor_module.time, "monotonic", side_effect=now),
            mock.patch.object(
                process_supervisor_module.tempfile,
                "mkdtemp",
                side_effect=fail_scratch,
            ),
            self.assertRaises(ProviderBoundaryFailure),
        ):
            supervisor.execute(
                b"request",
                worker_key=b"k" * 32,
                boundary=_control(),
                turn_timeout_ms=1_000,
            )
        self.assertEqual(["clock", "scratch"], operations)

    def test_broker_waits_for_authenticated_parent_start_before_worker_setup(self) -> None:
        parent, child = socket.socketpair()
        key = b"g" * 32
        nonce = "56" * 32
        called = threading.Event()
        failures: list[BaseException] = []
        scratch = self.enterContext(tempfile.TemporaryDirectory(prefix="worldforge-gate-test-"))

        def invoke() -> None:
            try:
                process_supervisor_module._linux_broker_process_entry(
                    child,
                    key,
                    nonce,
                    b"w" * 32,
                    b"request",
                    scratch,
                )
            except SystemExit:
                return
            except BaseException as exc:
                failures.append(exc)

        with mock.patch.object(
            process_supervisor_module,
            "_linux_broker_main",
            side_effect=lambda *_args, **_kwargs: called.set() or 0,
        ):
            thread = threading.Thread(target=invoke)
            thread.start()
            time.sleep(0.05)
            self.assertFalse(called.is_set())
            parent.sendall(
                process_supervisor_module._encode_control(
                    kind="start",
                    sequence=0,
                    nonce=nonce,
                    payload={},
                    key=key,
                )
            )
            thread.join(timeout=1)
        parent.close()
        self.assertFalse(thread.is_alive())
        self.assertEqual([], failures)
        self.assertTrue(called.is_set())

    def test_broker_gate_failure_removes_parent_scratch_without_starting_worker(self) -> None:
        parent, child = socket.socketpair()
        called = threading.Event()
        failures: list[BaseException] = []
        with tempfile.TemporaryDirectory() as directory:
            scratch = Path(directory) / "scratch"
            scratch.mkdir()

            def invoke() -> None:
                try:
                    process_supervisor_module._linux_broker_process_entry(
                        child,
                        b"g" * 32,
                        "78" * 32,
                        b"w" * 32,
                        b"request",
                        str(scratch),
                    )
                except SystemExit:
                    return
                except BaseException as exc:
                    failures.append(exc)

            with mock.patch.object(
                process_supervisor_module,
                "_linux_broker_main",
                side_effect=lambda *_args, **_kwargs: called.set() or 0,
            ):
                thread = threading.Thread(target=invoke)
                thread.start()
                parent.close()
                thread.join(timeout=1)
            self.assertFalse(thread.is_alive())
            self.assertEqual([], failures)
            self.assertFalse(called.is_set())
            self.assertFalse(scratch.exists())

    def test_zombie_broker_with_adopted_orphan_never_proves_empty(self) -> None:
        script = r'''
import os
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from worldforge.agent_harness import process_supervisor as ps

ps._set_linux_subreaper()
with tempfile.TemporaryDirectory() as directory:
    marker = Path(directory) / "orphan.pid"
    code = """
import os, time
from pathlib import Path
child = os.fork()
if child == 0:
    for descriptor in (0, 1, 2):
        try:
            os.close(descriptor)
        except OSError:
            pass
    time.sleep(30)
    os._exit(0)
Path(%r).write_text(str(child), encoding='ascii')
os._exit(0)
""" % str(marker)
    root = subprocess.Popen((sys.executable, "-c", code), close_fds=True)
    deadline = time.monotonic() + 2
    entry = None
    while time.monotonic() < deadline:
        entry = ps._proc_identity(root.pid)
        if marker.is_file() and entry is not None and entry[2] == "Z":
            break
        time.sleep(0.005)
    if entry is None or entry[2] != "Z" or not marker.is_file():
        raise SystemExit(10)
    orphan = int(marker.read_text(encoding="ascii"))
    if not Path(f"/proc/{orphan}").exists():
        raise SystemExit(11)
    class Broker:
        def join(self, timeout):
            root.wait(timeout=timeout)
        def is_alive(self):
            return root.returncode is None
        def kill(self):
            root.kill()
        def close(self):
            return None
    identity = ps._ProcessIdentity(root.pid, entry[1])
    try:
        if ps._cleanup_linux_broker_domain(
            broker=Broker(), broker_identity=identity, tracked={}
        ):
            raise SystemExit(12)
        if not Path(f"/proc/{orphan}").exists():
            raise SystemExit(13)
    finally:
        try:
            os.kill(orphan, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            os.waitpid(orphan, 0)
        except ChildProcessError:
            pass
'''
        completed = subprocess.run(
            (sys.executable, "-c", script),
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        self.assertEqual(0, completed.returncode, completed.stderr)

    def test_parent_owned_scratch_is_removed_after_broker_death(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            scratch = Path(directory) / "parent-owned-scratch"
            scratch.mkdir()
            supervisor = OneShotProviderSupervisor(turn_timeout_ms=2_000)
            killed = threading.Event()

            def kill_broker() -> None:
                deadline = time.monotonic() + 2
                while time.monotonic() < deadline:
                    pid = supervisor.active_broker_pid
                    worker = supervisor.active_worker_pid
                    if pid is not None and worker is not None:
                        os.kill(pid, signal.SIGKILL)
                        killed.set()
                        return
                    time.sleep(0.001)

            thread = threading.Thread(target=kill_broker)
            with mock.patch.object(
                process_supervisor_module.tempfile,
                "mkdtemp",
                return_value=str(scratch),
            ):
                thread.start()
                with self.assertRaises(ProviderBoundaryIndeterminate):
                    supervisor.turn(
                        _turn_request(_case("sleep", milliseconds=1_000)),
                        boundary=_control(),
                    )
                thread.join(timeout=2)
            self.assertTrue(killed.is_set())
            self.assertFalse(scratch.exists())


if __name__ == "__main__":
    unittest.main()
