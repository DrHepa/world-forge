from __future__ import annotations

import copy
import errno
import hashlib
import hmac
import json
import multiprocessing
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from unittest import mock

from tests.agent_harness_fakes import FakeCancellation, FakeClock
from tests.test_agent_execution_kernel import _request
from tests.test_agent_provider_governance import _execution_selection
from tests.test_agent_runtime_dispatch import _documents_for_runtime
from worldforge.agent_harness import AgentEventLog, AgentExecutionCoordinator, CapabilityBroker
from worldforge.agent_harness import process_supervisor as process_supervisor_module
from worldforge.agent_harness import worker_protocol as worker_protocol_module
from worldforge.agent_harness.kernel import AgentExecutionKernel, KernelError
from worldforge.agent_harness.loopback_gateway import (
    LoopbackGatewayError,
    LoopbackGatewayIndeterminate,
    LoopbackGatewayPolicy,
    LoopbackGatewayStopped,
    execute_loopback_exchange,
    parse_loopback_http_response,
)
from worldforge.agent_harness.loopback_protocol import (
    LoopbackProtocolError,
    LoopbackProtocolSession,
    build_loopback_request_frame,
    build_loopback_response_frame,
    parse_loopback_request_frame,
    parse_loopback_response_frame,
)
from worldforge.agent_harness.ports import (
    ProviderBoundaryControl,
    ProviderTurnRequest,
    ProviderTurnResult,
    ProviderUsage,
)
from worldforge.agent_harness.process_supervisor import (
    ProviderBoundaryFailure,
    ProviderBoundaryIndeterminate,
)
from worldforge.agent_harness.provider_catalog import ProviderExecutionSelection
from worldforge.agent_harness.provider_egress import _provider_worker_launcher_source
from worldforge.agent_harness.provider_governance import (
    InMemoryProviderGovernanceAuthority,
    ProviderGovernanceDecision,
)
from worldforge.agent_harness.supervisor import OneShotProviderSupervisor
from worldforge.agent_harness.worker_protocol import (
    WorkerProtocolError,
    build_result_frame,
    parse_result_frame,
)
from worldforge.agent_harness.worker_registry import (
    _CodeOwnedRuntimeKey,
    code_owned_provider_catalog,
    runtime_spec,
)

_RUNTIME = {
    "id": "worldforge_deterministic_probe_provider",
    "revision": 3,
    "content_hash": "1" * 64,
}
_NONCE = "2" * 64
_REQUEST_HASH = "3" * 64
_KEY = b"k" * 32


def _early_final_worker_source(delay_seconds: float) -> str:
    return f"""import hashlib
import hmac
import json
import sys
import time

def read_exact(size):
    data = bytearray()
    while len(data) < size:
        chunk = sys.stdin.buffer.read(size - len(data))
        if not chunk:
            raise EOFError()
        data.extend(chunk)
    return bytes(data)

def read_frame():
    size = int.from_bytes(read_exact(4), "big")
    return json.loads(read_exact(size).decode("utf-8"))

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")

def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()

def authenticated(document, key):
    result = dict(document)
    result["mac"] = hmac.new(key, canonical(document), hashlib.sha256).hexdigest()
    return result

def write_frame(document):
    raw = canonical(document)
    sys.stdout.buffer.write(len(raw).to_bytes(4, "big") + raw)
    sys.stdout.buffer.flush()

key = read_exact(32)
request = read_frame()
context = read_frame()
body = {{"probe": "early-final"}}
gateway = authenticated({{
    "body": body,
    "body_hash": digest(body),
    "body_length": len(canonical(body)),
    "format": "world-forge.private.loopback_gateway_request",
    "format_version": 1,
    "gateway_policy_hash": context["gateway_policy_hash"],
    "nonce": context["nonce"],
    "original_request_hash": context["original_request_hash"],
    "runtime": context["runtime"],
    "sequence": 0,
}}, key)
write_frame(gateway)
time.sleep({delay_seconds!r})
result = {{
    "artifact_proposals": [],
    "completed": True,
    "memory_proposals": [],
    "private_output": {{"early": True}},
    "tool_calls": [],
    "tool_exposure_requests": [],
    "usage": {{
        "cached_input_tokens": 0,
        "cost_minor_units": 0,
        "currency": "USD",
        "input_tokens": 1,
        "output_tokens": 1,
    }},
}}
final = authenticated({{
    "format": "world-forge.private.provider_turn_result",
    "format_version": 1,
    "nonce": request["nonce"],
    "request_hash": request["request_hash"],
    "result": result,
    "result_hash": digest(result),
    "runtime": request["runtime"],
}}, key)
write_frame(final)
time.sleep(0.15)
"""


def _loopback_selection(policy: LoopbackGatewayPolicy) -> ProviderExecutionSelection:
    catalog = code_owned_provider_catalog(gateway_policy=policy)
    spec = runtime_spec(
        _CodeOwnedRuntimeKey.DETERMINISTIC_PROBE,
        gateway_policy=policy,
    )
    return ProviderExecutionSelection.create(
        catalog_hash=catalog.catalog_hash,
        spec_hash=spec.content_hash,
        runtime_id=spec.runtime_id,
        runtime_revision=spec.runtime_revision,
        runtime_content_hash=spec.runtime_content_hash,
        non_secret_config_hash="4" * 64,
        disclosure_plan_hash="5" * 64,
        disclosed_data_classes=("private_test_payload",),
        base_payload_hash="6" * 64,
        tool_catalog_hash="7" * 64,
        max_turns=1,
        max_tool_calls=0,
        max_total_tokens=2,
        max_cost_minor_units=0,
        currency="USD",
        max_duration_ms=2_000,
        deadline_ms=None,
        pricing_policy_hash=None,
        credential_revision_id=None,
    )


class LoopbackGatewayPolicyTests(unittest.TestCase):
    def test_policy_canonicalizes_exact_numeric_loopback_authorities(self) -> None:
        ipv4 = LoopbackGatewayPolicy.create("http://127.0.0.1:43123")
        ipv6 = LoopbackGatewayPolicy.create("http://[::1]:43124")

        self.assertEqual((2, "127.0.0.1", 43123), (ipv4.family, ipv4.host, ipv4.port))
        self.assertEqual((10, "::1", 43124), (ipv6.family, ipv6.host, ipv6.port))
        self.assertEqual("/worldforge/v1/loopback-probe", ipv4.path)
        self.assertEqual(2_000, ipv4.total_deadline_ms)
        self.assertEqual(
            hashlib.sha256(ipv4.canonical_document).hexdigest(),
            ipv4.content_hash,
        )
        with self.assertRaises(FrozenInstanceError):
            ipv4.port = 1  # type: ignore[misc]

    def test_policy_rejects_hostile_origins_and_exact_type_subclasses(self) -> None:
        class Text(str):
            pass

        invalid = (
            Text("http://127.0.0.1:1"),
            "http://localhost:1",
            "http://127.0.0.2:1",
            "https://127.0.0.1:1",
            "http://127.0.0.1",
            "http://127.0.0.1:0",
            "http://127.0.0.1:65536",
            "http://user@127.0.0.1:1",
            "http://127.0.0.1:1/",
            "http://127.0.0.1:1?x=1",
            "http://127.0.0.1:1#fragment",
            "http://2130706433:1",
            "http://0177.0.0.1:1",
            "http://[0:0:0:0:0:0:0:1]:1",
        )
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(LoopbackGatewayError):
                LoopbackGatewayPolicy.create(value)


class LoopbackSideBandProtocolTests(unittest.TestCase):
    def test_authenticated_request_and_response_bind_every_correlation_field(self) -> None:
        policy = LoopbackGatewayPolicy.create("http://127.0.0.1:43123")
        body = {"execution_id": "exec_one", "turn_index": 0}
        request = build_loopback_request_frame(
            body,
            key=_KEY,
            nonce=_NONCE,
            runtime=_RUNTIME,
            original_request_hash=_REQUEST_HASH,
            gateway_policy_hash=policy.content_hash,
        )
        parsed = parse_loopback_request_frame(
            request,
            key=_KEY,
            nonce=_NONCE,
            runtime=_RUNTIME,
            original_request_hash=_REQUEST_HASH,
            gateway_policy_hash=policy.content_hash,
        )
        self.assertEqual(body, parsed.body)
        self.assertEqual(
            len(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()),
            parsed.body_length,
        )

        response_body = {"accepted": True, "proof": "deterministic"}
        response = build_loopback_response_frame(
            response_body,
            response_challenge="8" * 64,
            key=_KEY,
            nonce=_NONCE,
            runtime=_RUNTIME,
            original_request_hash=_REQUEST_HASH,
            gateway_policy_hash=policy.content_hash,
        )
        parsed_response = parse_loopback_response_frame(
            response,
            key=_KEY,
            nonce=_NONCE,
            runtime=_RUNTIME,
            original_request_hash=_REQUEST_HASH,
            gateway_policy_hash=policy.content_hash,
        )
        self.assertEqual(response_body, parsed_response.body)
        self.assertEqual("8" * 64, parsed_response.response_challenge)
        self.assertRegex(parsed_response.exchange_hash or "", r"^[0-9a-f]{64}$")
        second_response = parse_loopback_response_frame(
            build_loopback_response_frame(
                response_body,
                response_challenge="7" * 64,
                key=_KEY,
                nonce=_NONCE,
                runtime=_RUNTIME,
                original_request_hash=_REQUEST_HASH,
                gateway_policy_hash=policy.content_hash,
            ),
            key=_KEY,
            nonce=_NONCE,
            runtime=_RUNTIME,
            original_request_hash=_REQUEST_HASH,
            gateway_policy_hash=policy.content_hash,
        )
        self.assertNotEqual(parsed_response.exchange_hash, second_response.exchange_hash)

    def test_gateway_final_requires_exact_response_bound_proof(self) -> None:
        result = ProviderTurnResult(
            private_output={"accepted": True},
            usage=ProviderUsage(1, 1, 0, 0, "USD"),
            completed=True,
        )
        ordinary = build_result_frame(
            result,
            key=_KEY,
            nonce=_NONCE,
            request_hash=_REQUEST_HASH,
            runtime_key=_CodeOwnedRuntimeKey.DETERMINISTIC_PROBE,
        )
        exchange_hash = "9" * 64

        with self.assertRaises(WorkerProtocolError):
            worker_protocol_module._strip_gateway_result_proof(
                ordinary,
                key=_KEY,
                nonce=_NONCE,
                request_hash=_REQUEST_HASH,
                runtime_key=_CodeOwnedRuntimeKey.DETERMINISTIC_PROBE,
                expected_exchange_hash=exchange_hash,
            )

        document = json.loads(ordinary[4:].decode("utf-8"))
        document["gateway_exchange_hash"] = exchange_hash
        unsigned = {name: value for name, value in document.items() if name != "mac"}
        document["mac"] = hmac.new(
            _KEY,
            json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode(),
            hashlib.sha256,
        ).hexdigest()
        encoded = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
        bound = len(encoded).to_bytes(4, "big") + encoded

        stripped = worker_protocol_module._strip_gateway_result_proof(
            bound,
            key=_KEY,
            nonce=_NONCE,
            request_hash=_REQUEST_HASH,
            runtime_key=_CodeOwnedRuntimeKey.DETERMINISTIC_PROBE,
            expected_exchange_hash=exchange_hash,
        )
        self.assertEqual(
            result,
            parse_result_frame(
                stripped,
                key=_KEY,
                nonce=_NONCE,
                request_hash=_REQUEST_HASH,
                runtime_key=_CodeOwnedRuntimeKey.DETERMINISTIC_PROBE,
            ),
        )
        for hostile in (
            ordinary + bound,
            bound + ordinary,
            bound + bound,
            bound + b"trailing",
        ):
            with self.assertRaises(WorkerProtocolError):
                worker_protocol_module._strip_gateway_result_proof(
                    hostile,
                    key=_KEY,
                    nonce=_NONCE,
                    request_hash=_REQUEST_HASH,
                    runtime_key=_CodeOwnedRuntimeKey.DETERMINISTIC_PROBE,
                    expected_exchange_hash=exchange_hash,
                )
        with self.assertRaises(WorkerProtocolError):
            worker_protocol_module._strip_gateway_result_proof(
                bound,
                key=_KEY,
                nonce=_NONCE,
                request_hash=_REQUEST_HASH,
                runtime_key=_CodeOwnedRuntimeKey.DETERMINISTIC_PROBE,
                expected_exchange_hash="a" * 64,
            )
        for hostile_correlation in (
            {"key": b"x" * 32},
            {"nonce": "0" * 64},
            {"request_hash": "0" * 64},
            {"runtime_key": _CodeOwnedRuntimeKey.CONFORMANCE},
        ):
            arguments = {
                "key": _KEY,
                "nonce": _NONCE,
                "request_hash": _REQUEST_HASH,
                "runtime_key": _CodeOwnedRuntimeKey.DETERMINISTIC_PROBE,
                "expected_exchange_hash": exchange_hash,
            }
            arguments.update(hostile_correlation)
            with (
                self.subTest(hostile_correlation=hostile_correlation),
                self.assertRaises(WorkerProtocolError),
            ):
                worker_protocol_module._strip_gateway_result_proof(bound, **arguments)

    def test_protocol_rejects_mutation_trailing_overflow_replay_and_second_exchange(self) -> None:
        policy = LoopbackGatewayPolicy.create("http://127.0.0.1:43123")
        frame = build_loopback_request_frame(
            {"probe": "one"},
            key=_KEY,
            nonce=_NONCE,
            runtime=_RUNTIME,
            original_request_hash=_REQUEST_HASH,
            gateway_policy_hash=policy.content_hash,
        )
        cases = (
            {"key": b"x" * 32},
            {"nonce": "0" * 64},
            {"runtime": {**_RUNTIME, "revision": 4}},
            {"original_request_hash": "0" * 64},
            {"gateway_policy_hash": "0" * 64},
        )
        defaults = {
            "key": _KEY,
            "nonce": _NONCE,
            "runtime": _RUNTIME,
            "original_request_hash": _REQUEST_HASH,
            "gateway_policy_hash": policy.content_hash,
        }
        for override in cases:
            with self.subTest(override=override), self.assertRaises(LoopbackProtocolError):
                parse_loopback_request_frame(frame, **{**defaults, **override})
        with self.assertRaises(LoopbackProtocolError):
            parse_loopback_request_frame(frame + b"x", **defaults)
        with self.assertRaises(LoopbackProtocolError):
            build_loopback_request_frame({"x": "y" * 8193}, **defaults)

        session = LoopbackProtocolSession(**defaults)
        self.assertEqual({"probe": "one"}, session.accept_request(frame).body)
        with self.assertRaises(LoopbackProtocolError):
            session.accept_request(frame)
        response = session.build_response({"accepted": True}, response_challenge="8" * 64)
        self.assertEqual(
            {"accepted": True},
            parse_loopback_response_frame(response, **defaults).body,
        )
        with self.assertRaises(LoopbackProtocolError):
            session.build_response({"accepted": True}, response_challenge="8" * 64)


class StrictHttpResponseTests(unittest.TestCase):
    def test_accepts_only_canonical_json_with_exact_content_length(self) -> None:
        body = b'{"accepted":true}'
        response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/json\r\n"
            + f"Content-Length: {len(body)}\r\n".encode("ascii")
            + b"Connection: close\r\n\r\n"
            + body
        )
        self.assertEqual({"accepted": True}, parse_loopback_http_response(response))

    def test_rejects_malformed_or_ambiguous_http_framing(self) -> None:
        body = b'{"accepted":true}'
        invalid = (
            b"HTTP/1.1 302 Found\r\nContent-Length: 0\r\nContent-Type: application/json\r\n\r\n",
            b"HTTP/1.1 200 OK\nContent-Length: 0\nContent-Type: application/json\n\n",
            b"HTTP/1.1 200 OK\r\n Content-Length: 0\r\nContent-Type: application/json\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n"
            b"Content-Type: application/json\r\n\r\n0\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n"
            b"Content-Length: 0\r\nContent-Type: application/json\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n"
            b"Content-Length: 0\r\nContent-Type: application/json\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 99\r\nContent-Type: application/json\r\n\r\n"
            + body,
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n"
            b"Content-Type: application/json\r\nConnection: upgrade\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
            b"Content-Type: application/json\r\n\r\n{}trailer",
            b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n"
            b'Content-Type: application/json\r\n\r\n{"b": 1}',
        )
        for value in invalid:
            with self.subTest(value=value[:40]), self.assertRaises(LoopbackGatewayError):
                parse_loopback_http_response(value)


class ParentOwnedExchangeTests(unittest.TestCase):
    class _Socket:
        def __init__(self, response: bytes | BaseException) -> None:
            self.family = socket.AF_INET
            self.response = response
            self.sent = bytearray()
            self.closed = False
            self.close_calls = 0
            self.recv_calls = 0

        def setblocking(self, _value: bool) -> None:
            return None

        def connect_ex(self, address: object) -> int:
            if address != ("127.0.0.1", 43123):
                raise AssertionError("unexpected address")
            return 0

        def getpeername(self) -> tuple[str, int]:
            return ("127.0.0.1", 43123)

        def send(self, value: object) -> int:
            payload = bytes(value)
            self.sent.extend(payload)
            return len(payload)

        def recv(self, _count: int) -> bytes:
            self.recv_calls += 1
            if isinstance(self.response, BaseException):
                raise self.response
            value = self.response
            self.response = b""
            return value

        def close(self) -> None:
            self.close_calls += 1
            self.closed = True

    def test_preconnect_stop_has_zero_socket_effect(self) -> None:
        policy = LoopbackGatewayPolicy.create("http://127.0.0.1:43123")
        with mock.patch("worldforge.agent_harness.loopback_gateway.socket.socket") as constructor:
            with self.assertRaises(LoopbackGatewayStopped):
                execute_loopback_exchange(
                    policy,
                    {"probe": "one"},
                    boundary=lambda: "execution_cancelled",
                    started=time.monotonic(),
                )
        constructor.assert_not_called()

    def test_numeric_exchange_never_uses_dns_bind_listener_or_proxy_helpers(self) -> None:
        policy = LoopbackGatewayPolicy.create("http://127.0.0.1:43123")
        body = b'{"accepted":true}'
        response = (
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
            + f"Content-Length: {len(body)}\r\n".encode("ascii")
            + b"Connection: close\r\n\r\n"
            + body
        )
        stream = self._Socket(response)
        bomb = mock.Mock(side_effect=AssertionError("forbidden helper"))
        with (
            mock.patch(
                "worldforge.agent_harness.loopback_gateway.socket.socket", return_value=stream
            ),
            mock.patch("worldforge.agent_harness.loopback_gateway.socket.getaddrinfo", bomb),
            mock.patch("worldforge.agent_harness.loopback_gateway.socket.create_connection", bomb),
            mock.patch(
                "worldforge.agent_harness.loopback_gateway.select.select",
                side_effect=lambda readable, writable, _exceptional, _timeout: (
                    readable,
                    writable,
                    [],
                ),
            ),
        ):
            result = execute_loopback_exchange(
                policy,
                {"probe": "one"},
                boundary=lambda: None,
                started=time.monotonic(),
            )
        self.assertEqual({"accepted": True}, result)
        self.assertTrue(stream.closed)
        self.assertIn(b"Host: 127.0.0.1:43123\r\n", stream.sent)
        self.assertEqual(0, bomb.call_count)

    def test_failure_after_request_bytes_is_indeterminate_and_closes_socket(self) -> None:
        policy = LoopbackGatewayPolicy.create("http://127.0.0.1:43123")
        stream = self._Socket(OSError("RAW_SENTINEL_must_not_escape"))
        with (
            mock.patch(
                "worldforge.agent_harness.loopback_gateway.socket.socket", return_value=stream
            ),
            mock.patch(
                "worldforge.agent_harness.loopback_gateway.select.select",
                return_value=([stream], [stream], []),
            ),
        ):
            with self.assertRaises(LoopbackGatewayIndeterminate) as caught:
                execute_loopback_exchange(
                    policy,
                    {"private": "RAW_SENTINEL_must_not_escape"},
                    boundary=lambda: None,
                    started=time.monotonic(),
                )
        self.assertEqual("loopback_gateway_indeterminate", str(caught.exception))
        self.assertNotIn("RAW_SENTINEL", str(caught.exception))
        self.assertTrue(stream.closed)

    def test_raw_socket_setup_errors_are_bounded_and_close_exactly_once(self) -> None:
        policy = LoopbackGatewayPolicy.create("http://127.0.0.1:43123")

        with mock.patch(
            "worldforge.agent_harness.loopback_gateway.socket.socket",
            side_effect=OSError("RAW_CONSTRUCTOR_SENTINEL"),
        ):
            with self.assertRaises(LoopbackGatewayError) as caught:
                execute_loopback_exchange(
                    policy,
                    {"probe": "constructor"},
                    boundary=lambda: None,
                    started=time.monotonic(),
                )
        self.assertEqual("loopback_gateway_failed", str(caught.exception))

        for stage in ("setblocking", "connect", "getsockopt"):
            with self.subTest(stage=stage):
                stream = self._Socket(b"")
                if stage == "setblocking":
                    stream.setblocking = lambda _value: (_ for _ in ()).throw(  # type: ignore[method-assign]
                        OSError("RAW_SETUP_SENTINEL")
                    )
                elif stage == "connect":
                    stream.connect_ex = lambda _address: (_ for _ in ()).throw(  # type: ignore[method-assign]
                        OSError("RAW_SETUP_SENTINEL")
                    )
                else:
                    stream.connect_ex = lambda _address: errno.EINPROGRESS  # type: ignore[method-assign]
                    stream.getsockopt = lambda *_args: (_ for _ in ()).throw(  # type: ignore[attr-defined]
                        OSError("RAW_SETUP_SENTINEL")
                    )
                with (
                    mock.patch(
                        "worldforge.agent_harness.loopback_gateway.socket.socket",
                        return_value=stream,
                    ),
                    mock.patch(
                        "worldforge.agent_harness.loopback_gateway.select.select",
                        side_effect=lambda readable, writable, _exceptional, _timeout: (
                            readable,
                            writable,
                            [],
                        ),
                    ),
                ):
                    with self.assertRaises(LoopbackGatewayError) as caught:
                        execute_loopback_exchange(
                            policy,
                            {"probe": stage},
                            boundary=lambda: None,
                            started=time.monotonic(),
                        )
                self.assertEqual("loopback_gateway_failed", str(caught.exception))
                self.assertEqual(1, stream.close_calls)

    def test_deadline_during_nonblocking_connect_stops_before_request_bytes(self) -> None:
        policy = LoopbackGatewayPolicy.create("http://127.0.0.1:43123")
        stream = self._Socket(b"")
        stream.connect_ex = lambda _address: 115  # type: ignore[method-assign]
        polls = 0

        def boundary() -> str | None:
            nonlocal polls
            polls += 1
            return "execution_deadline_exceeded" if polls == 2 else None

        with (
            mock.patch(
                "worldforge.agent_harness.loopback_gateway.socket.socket",
                return_value=stream,
            ),
            mock.patch(
                "worldforge.agent_harness.loopback_gateway.select.select",
                side_effect=lambda readable, writable, _exceptional, _timeout: (
                    readable,
                    writable,
                    [],
                ),
            ),
        ):
            with self.assertRaises(LoopbackGatewayStopped):
                execute_loopback_exchange(
                    policy,
                    {"probe": "connect"},
                    boundary=boundary,
                    started=time.monotonic(),
                )
        self.assertEqual(b"", stream.sent)
        self.assertTrue(stream.closed)

    def test_cancellation_between_partial_writes_is_indeterminate(self) -> None:
        policy = LoopbackGatewayPolicy.create("http://127.0.0.1:43123")

        class PartialSocket(self._Socket):
            def send(self, value: object) -> int:
                payload = bytes(value)
                count = max(1, len(payload) // 2)
                self.sent.extend(payload[:count])
                return count

        stream = PartialSocket(b"")
        with (
            mock.patch(
                "worldforge.agent_harness.loopback_gateway.socket.socket",
                return_value=stream,
            ),
            mock.patch(
                "worldforge.agent_harness.loopback_gateway.select.select",
                side_effect=lambda readable, writable, _exceptional, _timeout: (
                    readable,
                    writable,
                    [],
                ),
            ),
        ):
            with self.assertRaises(LoopbackGatewayIndeterminate):
                execute_loopback_exchange(
                    policy,
                    {"probe": "send"},
                    boundary=lambda: "execution_cancelled" if stream.sent else None,
                    started=time.monotonic(),
                )
        self.assertGreater(len(stream.sent), 0)
        self.assertTrue(stream.closed)

    def test_revocation_during_read_and_after_response_validation_is_indeterminate(self) -> None:
        policy = LoopbackGatewayPolicy.create("http://127.0.0.1:43123")
        body = b'{"accepted":true}'
        response = (
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
            + f"Content-Length: {len(body)}\r\n".encode("ascii")
            + b"Connection: close\r\n\r\n"
            + body
        )

        for stage in ("read", "after_response"):
            with self.subTest(stage=stage):
                stream = self._Socket(response)
                polls = 0

                def boundary(
                    current_stage: str = stage,
                    current_stream: ParentOwnedExchangeTests._Socket = stream,
                ) -> str | None:
                    nonlocal polls
                    polls += 1
                    if (
                        current_stage == "read"
                        and current_stream.sent
                        and current_stream.recv_calls == 0
                    ):
                        return "provider_not_authorized"
                    if current_stage == "after_response" and polls == 8:
                        return "provider_not_authorized"
                    return None

                with (
                    mock.patch(
                        "worldforge.agent_harness.loopback_gateway.socket.socket",
                        return_value=stream,
                    ),
                    mock.patch(
                        "worldforge.agent_harness.loopback_gateway.select.select",
                        side_effect=lambda readable, writable, _exceptional, _timeout: (
                            readable,
                            writable,
                            [],
                        ),
                    ),
                ):
                    with self.assertRaises(LoopbackGatewayIndeterminate):
                        execute_loopback_exchange(
                            policy,
                            {"probe": stage},
                            boundary=boundary,
                            started=time.monotonic(),
                        )
                self.assertTrue(stream.closed)

    def test_uncertain_close_overrides_every_ordinary_exchange_outcome(self) -> None:
        policy = LoopbackGatewayPolicy.create("http://127.0.0.1:43123")
        body = b'{"accepted":true}'
        valid_response = (
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
            + f"Content-Length: {len(body)}\r\n".encode("ascii")
            + b"Connection: close\r\n\r\n"
            + body
        )

        class UncertainCloseSocket(self._Socket):
            def close(self) -> None:
                super().close()
                raise OSError("RAW_CLOSE_SENTINEL")

        def build(stage: str) -> tuple[UncertainCloseSocket, object]:
            stream = UncertainCloseSocket(
                OSError("RAW_READ_SENTINEL")
                if stage == "read"
                else b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
                if stage == "parser"
                else valid_response
            )
            if stage == "connect":
                stream.connect_ex = lambda _address: 111  # type: ignore[method-assign]
            if stage == "send":
                stream.send = lambda _value: (_ for _ in ()).throw(  # type: ignore[method-assign]
                    OSError("RAW_SEND_SENTINEL")
                )
            polls = 0

            def boundary() -> str | None:
                nonlocal polls
                polls += 1
                if stage == "pre_send_stop" and polls == 2:
                    return "execution_cancelled"
                if stage == "post_response" and stream.recv_calls >= 2:
                    return "provider_not_authorized"
                return None

            return stream, boundary

        for stage in (
            "connect",
            "pre_send_stop",
            "send",
            "read",
            "parser",
            "post_response",
            "success",
        ):
            with self.subTest(stage=stage):
                stream, boundary = build(stage)
                with (
                    mock.patch(
                        "worldforge.agent_harness.loopback_gateway.socket.socket",
                        return_value=stream,
                    ),
                    mock.patch(
                        "worldforge.agent_harness.loopback_gateway.select.select",
                        side_effect=lambda readable, writable, _exceptional, _timeout: (
                            readable,
                            writable,
                            [],
                        ),
                    ),
                ):
                    with self.assertRaises(LoopbackGatewayIndeterminate) as caught:
                        execute_loopback_exchange(
                            policy,
                            {"probe": stage},
                            boundary=boundary,  # type: ignore[arg-type]
                            started=time.monotonic(),
                        )
                self.assertEqual("loopback_gateway_indeterminate", str(caught.exception))
                self.assertEqual(1, stream.close_calls)

    def test_uncertain_close_preserves_primary_base_exception(self) -> None:
        policy = LoopbackGatewayPolicy.create("http://127.0.0.1:43123")

        class FatalBoundary(BaseException):
            pass

        class UncertainCloseSocket(self._Socket):
            def close(self) -> None:
                super().close()
                raise OSError("RAW_CLOSE_SENTINEL")

        stream = UncertainCloseSocket(b"")
        fatal = FatalBoundary("RAW_PRIMARY_SENTINEL")
        polls = 0

        def boundary() -> str | None:
            nonlocal polls
            polls += 1
            if polls == 2:
                raise fatal
            return None

        with (
            mock.patch(
                "worldforge.agent_harness.loopback_gateway.socket.socket",
                return_value=stream,
            ),
            mock.patch(
                "worldforge.agent_harness.loopback_gateway.select.select",
                side_effect=lambda readable, writable, _exceptional, _timeout: (
                    readable,
                    writable,
                    [],
                ),
            ),
        ):
            with self.assertRaises(FatalBoundary) as caught:
                execute_loopback_exchange(
                    policy,
                    {"probe": "fatal"},
                    boundary=boundary,
                    started=time.monotonic(),
                )
        self.assertIs(fatal, caught.exception)
        self.assertEqual(1, stream.close_calls)
        self.assertTrue(any("cleanup" in note for note in getattr(fatal, "__notes__", ())))

    def test_timeout_with_uncertain_close_is_indeterminate_before_any_request_byte(
        self,
    ) -> None:
        policy = LoopbackGatewayPolicy.create("http://127.0.0.1:43123")

        class UncertainCloseSocket(self._Socket):
            def connect_ex(self, _address: object) -> int:
                return errno.EINPROGRESS

            def close(self) -> None:
                super().close()
                raise OSError("RAW_CLOSE_SENTINEL")

        stream = UncertainCloseSocket(b"")
        with (
            mock.patch(
                "worldforge.agent_harness.loopback_gateway.socket.socket",
                return_value=stream,
            ),
            mock.patch(
                "worldforge.agent_harness.loopback_gateway.time.monotonic",
                side_effect=(100.0, 102.1),
            ),
        ):
            with self.assertRaises(LoopbackGatewayIndeterminate) as caught:
                execute_loopback_exchange(
                    policy,
                    {"probe": "timeout"},
                    boundary=lambda: None,
                    started=100.0,
                )
        self.assertEqual("loopback_gateway_indeterminate", str(caught.exception))
        self.assertEqual(b"", stream.sent)
        self.assertEqual(1, stream.close_calls)

    def test_private_turn_deadline_preempts_policy_and_bounds_clock_failures(self) -> None:
        policy = LoopbackGatewayPolicy.create("http://127.0.0.1:43123")
        stream = self._Socket(b"")
        stream.connect_ex = lambda _address: errno.EINPROGRESS  # type: ignore[method-assign]
        with (
            mock.patch(
                "worldforge.agent_harness.loopback_gateway.socket.socket",
                return_value=stream,
            ),
            mock.patch(
                "worldforge.agent_harness.loopback_gateway.time.monotonic",
                side_effect=(100.0, 100.21),
            ),
        ):
            with self.assertRaises(LoopbackGatewayError):
                execute_loopback_exchange(
                    policy,
                    {"probe": "private-timeout"},
                    boundary=lambda: None,
                    started=100.0,
                    private_deadline=100.2,
                )
        self.assertEqual(b"", stream.sent)
        self.assertEqual(1, stream.close_calls)

        body = b'{"accepted":true}'
        response = (
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
            + f"Content-Length: {len(body)}\r\n".encode("ascii")
            + b"Connection: close\r\n\r\n"
            + body
        )
        stream = self._Socket(response)
        with (
            mock.patch(
                "worldforge.agent_harness.loopback_gateway.socket.socket",
                return_value=stream,
            ),
            mock.patch(
                "worldforge.agent_harness.loopback_gateway.select.select",
                side_effect=lambda readable, writable, _exceptional, _timeout: (
                    readable,
                    writable,
                    [],
                ),
            ),
            mock.patch(
                "worldforge.agent_harness.loopback_gateway.time.monotonic",
                side_effect=(100.0, 100.0, 100.0, 100.0, 100.21),
            ),
        ):
            with self.assertRaises(LoopbackGatewayIndeterminate):
                execute_loopback_exchange(
                    policy,
                    {"probe": "post-response-private-timeout"},
                    boundary=lambda: None,
                    started=100.0,
                    private_deadline=100.2,
                )
        self.assertGreater(len(stream.sent), 0)
        self.assertEqual(1, stream.close_calls)

        with (
            mock.patch("worldforge.agent_harness.loopback_gateway.socket.socket") as constructor,
            mock.patch(
                "worldforge.agent_harness.loopback_gateway.time.monotonic",
                side_effect=RuntimeError("RAW_CLOCK_SENTINEL"),
            ),
        ):
            with self.assertRaises(LoopbackGatewayError) as caught:
                execute_loopback_exchange(
                    policy,
                    {"probe": "clock-failure"},
                    boundary=lambda: None,
                    started=100.0,
                    private_deadline=100.2,
                )
        self.assertEqual("loopback_gateway_failed", str(caught.exception))
        constructor.assert_not_called()

        with self.assertRaises(LoopbackGatewayError):
            execute_loopback_exchange(
                policy,
                {"probe": "hostile-deadline-type"},
                boundary=lambda: None,
                started=100.0,
                private_deadline=101,  # type: ignore[arg-type]
            )


class LoopbackRuntimeAuthorityTests(unittest.TestCase):
    def test_exact_policy_advances_only_probe_spec_and_keeps_two_runtime_ids(self) -> None:
        policy = LoopbackGatewayPolicy.create("http://127.0.0.1:43123")
        catalog = code_owned_provider_catalog(gateway_policy=policy)
        conformance = runtime_spec(_CodeOwnedRuntimeKey.CONFORMANCE)
        probe = runtime_spec(
            _CodeOwnedRuntimeKey.DETERMINISTIC_PROBE,
            gateway_policy=policy,
        )

        self.assertEqual(2, len(catalog.specs))
        self.assertEqual(
            (
                "worldforge_conformance_provider",
                "worldforge_deterministic_probe_provider",
            ),
            tuple(spec.runtime_id for spec in catalog.specs),
        )
        self.assertEqual(conformance, catalog.specs[0])
        self.assertEqual("loopback", probe.network_scope)
        self.assertEqual(policy.endpoint_origin, probe.endpoint_origin)
        self.assertEqual(policy.content_hash, probe.endpoint_policy_hash)
        self.assertIsNotNone(probe.egress_enforcement_hash)
        self.assertIsNotNone(probe.telemetry_attestation_hash)
        self.assertEqual(probe, catalog.specs[1])

    def test_production_launcher_keeps_worker_direct_sockets_denied(self) -> None:
        source = """
import errno
import json
import socket

result = {}
for name, family in (("ipv4", socket.AF_INET), ("ipv6", socket.AF_INET6), ("unix", socket.AF_UNIX)):
    try:
        socket.socket(family, socket.SOCK_STREAM)
    except OSError as exc:
        result[name] = exc.errno
    else:
        result[name] = 0
print(json.dumps(result, sort_keys=True, separators=(",", ":")))
"""
        completed = subprocess.run(
            (
                sys.executable,
                "-I",
                "-B",
                "-S",
                "-u",
                "-X",
                "utf8",
                "-c",
                _provider_worker_launcher_source(source),
            ),
            capture_output=True,
            close_fds=True,
            timeout=3,
            check=False,
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual(
            {"ipv4": 1, "ipv6": 1, "unix": 1},
            json.loads(completed.stdout),
        )

    def test_supervisor_freezes_exact_policy_catalog_and_selection_without_connecting(self) -> None:
        policy = LoopbackGatewayPolicy.create("http://127.0.0.1:43123")
        catalog = code_owned_provider_catalog(gateway_policy=policy)
        selection = _loopback_selection(policy)

        supervisor = OneShotProviderSupervisor.for_selection(
            selection,
            gateway_policy=policy,
            turn_timeout_ms=2_000,
        )

        self.assertEqual(policy, supervisor.gateway_policy)
        self.assertEqual(catalog, supervisor.provider_catalog)
        self.assertEqual(selection, supervisor.provider_selection)
        self.assertEqual(0, supervisor.spawn_count)

        kernel = AgentExecutionKernel(
            provider=supervisor,
            broker=object(),  # type: ignore[arg-type]
            journal=object(),  # type: ignore[arg-type]
            clock=object(),  # type: ignore[arg-type]
            cancellation=object(),  # type: ignore[arg-type]
            provider_catalog=catalog,
        )
        self.assertEqual(supervisor, kernel.provider)

        other_policy = LoopbackGatewayPolicy.create("http://127.0.0.1:43124")
        with self.assertRaises(KernelError):
            AgentExecutionKernel(
                provider=supervisor,
                broker=object(),  # type: ignore[arg-type]
                journal=object(),  # type: ignore[arg-type]
                clock=object(),  # type: ignore[arg-type]
                cancellation=object(),  # type: ignore[arg-type]
                provider_catalog=code_owned_provider_catalog(gateway_policy=other_policy),
            )
        self.assertEqual(0, supervisor.spawn_count)

    def test_kernel_rejects_duck_typed_loopback_authority_before_effects(self) -> None:
        policy = LoopbackGatewayPolicy.create("http://127.0.0.1:43123")
        catalog = code_owned_provider_catalog(gateway_policy=policy)
        selection = _loopback_selection(policy)
        spec = runtime_spec(
            _CodeOwnedRuntimeKey.DETERMINISTIC_PROBE,
            gateway_policy=policy,
        )

        class ForgedProvider:
            runtime_binding = spec.runtime_binding
            provider_catalog = catalog
            provider_selection = selection

            def __init__(self) -> None:
                self.turn_calls = 0

            def turn(self, *_args: object, **_kwargs: object) -> object:
                self.turn_calls += 1
                socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                raise AssertionError("forged provider turn ran")

        provider = ForgedProvider()
        with mock.patch(
            "tests.test_agent_loopback_gateway.socket.socket",
            side_effect=AssertionError("socket effect occurred"),
        ) as socket_constructor:
            with self.assertRaises(KernelError):
                AgentExecutionKernel(
                    provider=provider,  # type: ignore[arg-type]
                    broker=object(),  # type: ignore[arg-type]
                    journal=object(),  # type: ignore[arg-type]
                    clock=object(),  # type: ignore[arg-type]
                    cancellation=object(),  # type: ignore[arg-type]
                    provider_catalog=catalog,
                )
        self.assertEqual(0, provider.turn_calls)
        socket_constructor.assert_not_called()

    def test_kernel_rejects_subclass_object_new_and_rebound_gateway_authority(self) -> None:
        policy = LoopbackGatewayPolicy.create("http://127.0.0.1:43123")
        catalog = code_owned_provider_catalog(gateway_policy=policy)
        selection = _loopback_selection(policy)
        genuine = OneShotProviderSupervisor.for_selection(
            selection,
            gateway_policy=policy,
            turn_timeout_ms=2_000,
        )

        class SupervisorSubclass(OneShotProviderSupervisor):
            @classmethod
            def _require_gateway_authority(
                cls, _provider: object, _catalog: object
            ) -> ProviderExecutionSelection:
                return selection

        forged_subclass = object.__new__(SupervisorSubclass)
        object.__setattr__(forged_subclass, "_authority", genuine._authority)
        forged_exact = object.__new__(OneShotProviderSupervisor)
        object.__setattr__(forged_exact, "_authority", genuine._authority)

        for provider in (forged_subclass, forged_exact):
            with self.subTest(provider_type=type(provider).__name__):
                with self.assertRaises(KernelError):
                    AgentExecutionKernel(
                        provider=provider,
                        broker=object(),  # type: ignore[arg-type]
                        journal=object(),  # type: ignore[arg-type]
                        clock=object(),  # type: ignore[arg-type]
                        cancellation=object(),  # type: ignore[arg-type]
                        provider_catalog=catalog,
                    )

        with self.assertRaises(AttributeError):
            genuine._authority = genuine._authority  # type: ignore[misc]

    def test_kernel_rejects_closed_consumed_and_mutated_gateway_capability(self) -> None:
        policy = LoopbackGatewayPolicy.create("http://127.0.0.1:43123")
        catalog = code_owned_provider_catalog(gateway_policy=policy)
        selection = _loopback_selection(policy)

        for state in ("closed", "consumed"):
            with self.subTest(state=state):
                provider = OneShotProviderSupervisor.for_selection(
                    selection,
                    gateway_policy=policy,
                    turn_timeout_ms=2_000,
                )
                capability = provider._authority.gateway_capability
                self.assertIsNotNone(capability)
                with self.assertRaises(AttributeError):
                    capability._state = state  # type: ignore[union-attr,misc]
                object.__setattr__(capability, "_state", state)
                with self.assertRaises(KernelError):
                    AgentExecutionKernel(
                        provider=provider,
                        broker=object(),  # type: ignore[arg-type]
                        journal=object(),  # type: ignore[arg-type]
                        clock=object(),  # type: ignore[arg-type]
                        cancellation=object(),  # type: ignore[arg-type]
                        provider_catalog=catalog,
                    )
                self.assertEqual(0, provider.spawn_count)

        provider = OneShotProviderSupervisor.for_selection(
            selection,
            gateway_policy=policy,
            turn_timeout_ms=2_000,
        )
        object.__setattr__(
            provider,
            "_authority",
            replace(provider._authority, dispatch=lambda *_args, **_kwargs: None),
        )
        with self.assertRaises(KernelError):
            AgentExecutionKernel(
                provider=provider,
                broker=object(),  # type: ignore[arg-type]
                journal=object(),  # type: ignore[arg-type]
                clock=object(),  # type: ignore[arg-type]
                cancellation=object(),  # type: ignore[arg-type]
                provider_catalog=catalog,
            )
        self.assertEqual(0, provider.spawn_count)

        provider = OneShotProviderSupervisor.for_selection(
            selection,
            gateway_policy=policy,
            turn_timeout_ms=2_000,
        )
        kernel = AgentExecutionKernel(
            provider=provider,
            broker=object(),  # type: ignore[arg-type]
            journal=object(),  # type: ignore[arg-type]
            clock=object(),  # type: ignore[arg-type]
            cancellation=object(),  # type: ignore[arg-type]
            provider_catalog=catalog,
        )
        object.__setattr__(provider._authority.gateway_capability, "_state", "closed")
        with self.assertRaises(KernelError):
            kernel.execute(object())  # type: ignore[arg-type]
        self.assertEqual(0, provider.spawn_count)

    def test_gateway_issuance_anchor_rejects_identical_authority_and_capability_copies(
        self,
    ) -> None:
        policy = LoopbackGatewayPolicy.create("http://127.0.0.1:43123")
        catalog = code_owned_provider_catalog(gateway_policy=policy)
        selection = _loopback_selection(policy)

        def issued() -> OneShotProviderSupervisor:
            return OneShotProviderSupervisor.for_selection(
                selection,
                gateway_policy=policy,
                turn_timeout_ms=2_000,
            )

        def copied_capability(provider: OneShotProviderSupervisor) -> object:
            original = provider._authority.gateway_capability
            self.assertIsNotNone(original)
            copied = object.__new__(type(original))
            for slot in type(original).__slots__:
                object.__setattr__(copied, slot, object.__getattribute__(original, slot))
            return copied

        variants: list[tuple[str, OneShotProviderSupervisor]] = []
        provider = issued()
        object.__setattr__(provider, "_authority", replace(provider._authority))
        variants.append(("identical_authority", provider))

        provider = issued()
        capability_copy = copied_capability(provider)
        object.__setattr__(
            provider,
            "_authority",
            replace(provider._authority, gateway_capability=capability_copy),
        )
        variants.append(("copied_capability_and_authority", provider))

        provider = issued()
        capability_copy = copied_capability(provider)
        with self.assertRaises(FrozenInstanceError):
            provider._authority.gateway_capability = capability_copy  # type: ignore[misc]
        object.__setattr__(
            provider._authority,
            "gateway_capability",
            capability_copy,
        )
        variants.append(("copied_capability_in_issued_authority", provider))

        provider = issued()
        variants.append(("shallow_provider_copy", copy.copy(provider)))

        provider = issued()
        forged_provider = object.__new__(OneShotProviderSupervisor)
        object.__setattr__(forged_provider, "_authority", provider._authority)
        object.__setattr__(
            forged_provider,
            "_gateway_authority_validator",
            provider._gateway_authority_validator,
        )
        variants.append(("object_new_with_copied_anchor", forged_provider))

        provider = issued()
        try:
            deep_provider = copy.deepcopy(provider)
        except (copy.Error, TypeError):
            pass
        else:
            variants.append(("deep_provider_copy", deep_provider))

        for name, copied_provider in variants:
            with self.subTest(name=name):
                with mock.patch(
                    "tests.test_agent_loopback_gateway.socket.socket",
                    side_effect=AssertionError("network effect occurred"),
                ) as socket_constructor:
                    with self.assertRaises(KernelError):
                        AgentExecutionKernel(
                            provider=copied_provider,
                            broker=object(),  # type: ignore[arg-type]
                            journal=object(),  # type: ignore[arg-type]
                            clock=object(),  # type: ignore[arg-type]
                            cancellation=object(),  # type: ignore[arg-type]
                            provider_catalog=catalog,
                        )
                self.assertEqual(0, copied_provider.spawn_count)
                socket_constructor.assert_not_called()

        genuine = issued()
        anchor = genuine._gateway_authority_validator
        with self.assertRaises(AttributeError):
            genuine._gateway_authority_validator = anchor  # type: ignore[misc]
        with self.assertRaises(AttributeError):
            del genuine._gateway_authority_validator  # type: ignore[misc]
        AgentExecutionKernel(
            provider=genuine,
            broker=object(),  # type: ignore[arg-type]
            journal=object(),  # type: ignore[arg-type]
            clock=object(),  # type: ignore[arg-type]
            cancellation=object(),  # type: ignore[arg-type]
            provider_catalog=catalog,
        )

        genuine = issued()
        kernel = AgentExecutionKernel(
            provider=genuine,
            broker=object(),  # type: ignore[arg-type]
            journal=object(),  # type: ignore[arg-type]
            clock=object(),  # type: ignore[arg-type]
            cancellation=object(),  # type: ignore[arg-type]
            provider_catalog=catalog,
        )
        object.__setattr__(genuine, "_authority", replace(genuine._authority))
        with self.assertRaises(KernelError):
            kernel.execute(object())  # type: ignore[arg-type]
        self.assertEqual(0, genuine.spawn_count)

    def test_native_probe_uses_parent_gateway_and_returns_after_domain_empty(self) -> None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        policy = LoopbackGatewayPolicy.create(f"http://127.0.0.1:{port}")
        received: list[bytes] = []
        finished = threading.Event()

        def serve() -> None:
            try:
                connection, _address = listener.accept()
                with connection:
                    raw = bytearray()
                    while b"\r\n\r\n" not in raw:
                        raw.extend(connection.recv(4096))
                    headers, initial_body = bytes(raw).split(b"\r\n\r\n", 1)
                    length_line = next(
                        line
                        for line in headers.split(b"\r\n")
                        if line.startswith(b"Content-Length:")
                    )
                    length = int(length_line.split(b":", 1)[1])
                    body = bytearray(initial_body)
                    while len(body) < length:
                        body.extend(connection.recv(length - len(body)))
                    received.append(headers + b"\r\n\r\n" + bytes(body))
                    response_body = b'{"accepted":true,"source":"native-loopback"}'
                    connection.sendall(
                        b"HTTP/1.1 200 OK\r\n"
                        b"Content-Type: application/json\r\n"
                        + f"Content-Length: {len(response_body)}\r\n".encode("ascii")
                        + b"Connection: close\r\n\r\n"
                        + response_body
                    )
            finally:
                listener.close()
                finished.set()

        server = threading.Thread(target=serve, daemon=True)
        server.start()
        supervisor = OneShotProviderSupervisor.for_selection(
            _loopback_selection(policy),
            gateway_policy=policy,
            turn_timeout_ms=2_000,
        )
        result = supervisor.turn(
            ProviderTurnRequest(
                execution_id="exec_one",
                turn_index=0,
                private_input={"sentinel": "private-only"},
                history=({"role": "user", "text": "hello"},),
                tool_summaries=(),
                exposed_tools=(),
            ),
            boundary=ProviderBoundaryControl(lambda: None),
        )
        server.join(2)

        self.assertTrue(finished.is_set())
        self.assertEqual(
            {"accepted": True, "source": "native-loopback"},
            result.private_output["gateway_response"],
        )
        self.assertEqual(1, len(received))
        self.assertIn(b"POST /worldforge/v1/loopback-probe HTTP/1.1\r\n", received[0])
        self.assertIsNone(supervisor.active_broker_pid)
        self.assertIsNone(supervisor.active_worker_pid)

    def test_early_worker_final_never_crosses_response_bound_acceptance(self) -> None:
        fork_context = multiprocessing.get_context("fork")
        for delay_seconds in (0.0, 0.02):
            with self.subTest(delay_seconds=delay_seconds):
                listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                listener.bind(("127.0.0.1", 0))
                listener.listen(1)
                listener.settimeout(2)
                policy = LoopbackGatewayPolicy.create(
                    f"http://127.0.0.1:{listener.getsockname()[1]}"
                )
                accepted_count = [0]
                server_errors: list[BaseException] = []

                def serve(
                    listener: socket.socket = listener,
                    accepted_count: list[int] = accepted_count,
                    server_errors: list[BaseException] = server_errors,
                ) -> None:
                    try:
                        connection, _address = listener.accept()
                        accepted_count[0] += 1
                        with connection:
                            raw = bytearray()
                            while b"\r\n\r\n" not in raw:
                                raw.extend(connection.recv(4096))
                            headers, body = bytes(raw).split(b"\r\n\r\n", 1)
                            length = int(
                                next(
                                    line
                                    for line in headers.split(b"\r\n")
                                    if line.startswith(b"Content-Length:")
                                ).split(b":", 1)[1]
                            )
                            while len(body) < length:
                                body += connection.recv(length - len(body))
                            time.sleep(0.1)
                            response = b'{"accepted":true}'
                            connection.sendall(
                                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                                + f"Content-Length: {len(response)}\r\n".encode("ascii")
                                + b"Connection: close\r\n\r\n"
                                + response
                            )
                    except BaseException as exc:
                        server_errors.append(exc)
                    finally:
                        listener.close()

                def spawn_early_worker(
                    runtime_launch: object,
                    scratch: str,
                    delay_seconds: float = delay_seconds,
                ) -> subprocess.Popen[bytes]:
                    environment = dict(runtime_launch.environment)  # type: ignore[attr-defined]
                    return subprocess.Popen(
                        (
                            sys.executable,
                            "-I",
                            "-B",
                            "-S",
                            "-u",
                            "-X",
                            "utf8",
                            "-c",
                            _early_final_worker_source(delay_seconds),
                        ),
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        cwd=scratch,
                        env=environment,
                        shell=False,
                        close_fds=True,
                        pass_fds=(),
                    )

                server = threading.Thread(target=serve, daemon=True)
                server.start()
                activation, grant = _documents_for_runtime(_CodeOwnedRuntimeKey.DETERMINISTIC_PROBE)
                broker = CapabilityBroker()
                request = _request(activation, grant)
                catalog = code_owned_provider_catalog(gateway_policy=policy)
                selection = _execution_selection(
                    request,
                    broker,
                    catalog=catalog,
                    spec=runtime_spec(
                        _CodeOwnedRuntimeKey.DETERMINISTIC_PROBE,
                        gateway_policy=policy,
                    ),
                )
                request = replace(
                    request,
                    provider_approval_id="provider_approval_early_final_01",
                    provider_selection=selection,
                )
                authority = InMemoryProviderGovernanceAuthority()
                provider = OneShotProviderSupervisor.for_selection(
                    selection,
                    gateway_policy=policy,
                    turn_timeout_ms=1_000,
                )
                with (
                    tempfile.TemporaryDirectory() as temporary,
                    AgentEventLog(temporary) as journal,
                    mock.patch.object(
                        process_supervisor_module,
                        "_spawn_code_owned_worker",
                        new=spawn_early_worker,
                    ),
                    mock.patch.object(
                        process_supervisor_module.multiprocessing,
                        "get_context",
                        return_value=fork_context,
                    ),
                ):
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
                    authority.decide(
                        ProviderGovernanceDecision.create(
                            review=review,
                            reviewer_id="provider_reviewer_early_final_01",
                            outcome="approved",
                            expires_at_ms=5_000,
                        ),
                        expected_generation=0,
                        expected_review_hash=review.content_hash,
                    )
                    coordinator = AgentExecutionCoordinator(kernel=kernel, event_log=journal)
                    with self.assertRaises(ProviderBoundaryIndeterminate):
                        coordinator.execute(request)
                    replay = journal.replay_records(str(activation["execution_id"]))
                    self.assertEqual("open", replay.state)
                    self.assertIsNone(replay.receipt_bytes)

                server.join(2)
                self.assertEqual([], server_errors)
                self.assertEqual(1, accepted_count[0])
                self.assertEqual(1, provider.spawn_count)
                self.assertIsNone(provider.active_broker_pid)
                self.assertIsNone(provider.active_worker_pid)

    def test_private_turn_deadline_bounds_slow_post_send_gateway(self) -> None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(2)
        policy = LoopbackGatewayPolicy.create(f"http://127.0.0.1:{listener.getsockname()[1]}")
        accepted = 0

        def serve() -> None:
            nonlocal accepted
            try:
                connection, _address = listener.accept()
                accepted += 1
                with connection:
                    raw = bytearray()
                    while b"\r\n\r\n" not in raw:
                        raw.extend(connection.recv(4096))
                    headers, body = bytes(raw).split(b"\r\n\r\n", 1)
                    length = int(
                        next(
                            line
                            for line in headers.split(b"\r\n")
                            if line.startswith(b"Content-Length:")
                        ).split(b":", 1)[1]
                    )
                    while len(body) < length:
                        body += connection.recv(length - len(body))
                    time.sleep(1.0)
                    response = b'{"accepted":true}'
                    try:
                        connection.sendall(
                            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                            + f"Content-Length: {len(response)}\r\n".encode("ascii")
                            + b"Connection: close\r\n\r\n"
                            + response
                        )
                    except OSError:
                        pass
            finally:
                listener.close()

        server = threading.Thread(target=serve, daemon=True)
        server.start()
        activation, grant = _documents_for_runtime(_CodeOwnedRuntimeKey.DETERMINISTIC_PROBE)
        broker = CapabilityBroker()
        request = _request(activation, grant)
        catalog = code_owned_provider_catalog(gateway_policy=policy)
        selection = _execution_selection(
            request,
            broker,
            catalog=catalog,
            spec=runtime_spec(
                _CodeOwnedRuntimeKey.DETERMINISTIC_PROBE,
                gateway_policy=policy,
            ),
        )
        request = replace(
            request,
            provider_approval_id="provider_approval_private_deadline_01",
            provider_selection=selection,
        )
        authority = InMemoryProviderGovernanceAuthority()
        provider = OneShotProviderSupervisor.for_selection(
            selection,
            gateway_policy=policy,
            turn_timeout_ms=500,
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
            authority.decide(
                ProviderGovernanceDecision.create(
                    review=review,
                    reviewer_id="provider_reviewer_private_deadline_01",
                    outcome="approved",
                    expires_at_ms=5_000,
                ),
                expected_generation=0,
                expected_review_hash=review.content_hash,
            )
            coordinator = AgentExecutionCoordinator(kernel=kernel, event_log=journal)
            started = time.monotonic()
            with self.assertRaises(ProviderBoundaryIndeterminate):
                coordinator.execute(request)
            elapsed = time.monotonic() - started
            replay = journal.replay_records(str(activation["execution_id"]))
            self.assertEqual("open", replay.state)
            self.assertIsNone(replay.receipt_bytes)

        server.join(2)
        self.assertLess(elapsed, 1.5)
        self.assertEqual(1, accepted)
        self.assertEqual(1, provider.spawn_count)
        self.assertIsNone(provider.active_broker_pid)
        self.assertIsNone(provider.active_worker_pid)

    def test_concurrent_turn_is_rejected_before_second_spawn_or_connect(self) -> None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        policy = LoopbackGatewayPolicy.create(f"http://127.0.0.1:{listener.getsockname()[1]}")
        accepted = threading.Event()
        release = threading.Event()

        def serve() -> None:
            try:
                connection, _address = listener.accept()
                with connection:
                    raw = bytearray()
                    while b"\r\n\r\n" not in raw:
                        raw.extend(connection.recv(4096))
                    headers, body = bytes(raw).split(b"\r\n\r\n", 1)
                    length = int(
                        next(
                            line
                            for line in headers.split(b"\r\n")
                            if line.startswith(b"Content-Length:")
                        ).split(b":", 1)[1]
                    )
                    while len(body) < length:
                        body += connection.recv(length - len(body))
                    accepted.set()
                    release.wait(1)
                    response = b'{"accepted":true}'
                    connection.sendall(
                        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                        + f"Content-Length: {len(response)}\r\n".encode("ascii")
                        + b"Connection: close\r\n\r\n"
                        + response
                    )
            finally:
                listener.close()

        request = ProviderTurnRequest(
            execution_id="exec_one",
            turn_index=0,
            private_input={"probe": "concurrency"},
            history=(),
            tool_summaries=(),
            exposed_tools=(),
        )
        supervisor = OneShotProviderSupervisor.for_selection(
            _loopback_selection(policy),
            gateway_policy=policy,
            turn_timeout_ms=2_000,
        )
        server = threading.Thread(target=serve, daemon=True)
        first_errors: list[BaseException] = []

        def first_turn() -> None:
            try:
                supervisor.turn(request, boundary=ProviderBoundaryControl(lambda: None))
            except BaseException as exc:
                first_errors.append(exc)

        runner = threading.Thread(target=first_turn)
        server.start()
        runner.start()
        self.assertTrue(accepted.wait(1))
        with self.assertRaises(ProviderBoundaryFailure):
            supervisor.turn(request, boundary=ProviderBoundaryControl(lambda: None))
        self.assertEqual(1, supervisor.spawn_count)
        release.set()
        runner.join(2)
        server.join(2)

        self.assertEqual([], first_errors)
        self.assertEqual(1, supervisor.spawn_count)

    def test_kernel_governance_and_terminal_duplicate_perform_one_exchange(self) -> None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(2)
        port = listener.getsockname()[1]
        policy = LoopbackGatewayPolicy.create(f"http://127.0.0.1:{port}")
        accepted = 0

        def serve() -> None:
            nonlocal accepted
            try:
                connection, _address = listener.accept()
                accepted += 1
                with connection:
                    raw = bytearray()
                    while b"\r\n\r\n" not in raw:
                        raw.extend(connection.recv(4096))
                    headers, body = bytes(raw).split(b"\r\n\r\n", 1)
                    length = int(
                        next(
                            line
                            for line in headers.split(b"\r\n")
                            if line.startswith(b"Content-Length:")
                        ).split(b":", 1)[1]
                    )
                    while len(body) < length:
                        body += connection.recv(length - len(body))
                    response = b'{"accepted":true}'
                    connection.sendall(
                        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                        + f"Content-Length: {len(response)}\r\n".encode("ascii")
                        + b"Connection: close\r\n\r\n"
                        + response
                    )
            finally:
                listener.close()

        server = threading.Thread(target=serve, daemon=True)
        server.start()
        activation, grant = _documents_for_runtime(_CodeOwnedRuntimeKey.DETERMINISTIC_PROBE)
        broker = CapabilityBroker()
        request = _request(activation, grant)
        catalog = code_owned_provider_catalog(gateway_policy=policy)
        selection = _execution_selection(
            request,
            broker,
            catalog=catalog,
            spec=runtime_spec(
                _CodeOwnedRuntimeKey.DETERMINISTIC_PROBE,
                gateway_policy=policy,
            ),
        )
        request = replace(
            request,
            provider_approval_id="provider_approval_loopback_01",
            provider_selection=selection,
        )
        authority = InMemoryProviderGovernanceAuthority()
        provider = OneShotProviderSupervisor.for_selection(
            selection,
            gateway_policy=policy,
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
            authority.decide(
                ProviderGovernanceDecision.create(
                    review=review,
                    reviewer_id="provider_reviewer_loopback_01",
                    outcome="approved",
                    expires_at_ms=5_000,
                ),
                expected_generation=0,
                expected_review_hash=review.content_hash,
            )
            coordinator = AgentExecutionCoordinator(kernel=kernel, event_log=journal)
            first = coordinator.execute(request)
            duplicate = coordinator.execute(request)
        server.join(2)

        self.assertEqual("succeeded", first.result.outcome)
        self.assertEqual("existing_terminal", duplicate.disposition)
        self.assertEqual(1, accepted)
        self.assertEqual(1, provider.spawn_count)

    def test_post_send_failure_leaves_private_open_prefix_for_offline_recovery(
        self,
    ) -> None:
        request_sentinel = b"RAW_LOOPBACK_REQUEST_SENTINEL"
        response_sentinel = b"RAW_LOOPBACK_RESPONSE_SENTINEL"
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(2)
        policy = LoopbackGatewayPolicy.create(f"http://127.0.0.1:{listener.getsockname()[1]}")
        accepted = 0
        received: list[bytes] = []
        server_errors: list[BaseException] = []

        def serve() -> None:
            nonlocal accepted
            try:
                connection, _address = listener.accept()
                accepted += 1
                with connection:
                    raw = bytearray()
                    while b"\r\n\r\n" not in raw:
                        raw.extend(connection.recv(4096))
                    headers, body = bytes(raw).split(b"\r\n\r\n", 1)
                    length = int(
                        next(
                            line
                            for line in headers.split(b"\r\n")
                            if line.startswith(b"Content-Length:")
                        ).split(b":", 1)[1]
                    )
                    while len(body) < length:
                        body += connection.recv(length - len(body))
                    received.append(headers + b"\r\n\r\n" + body)
                    connection.sendall(
                        b"HTTP/1.1 200 OK\r\n"
                        b"Content-Type: application/json\r\n"
                        b"Content-Length: 99\r\n"
                        b"Connection: close\r\n\r\n"
                        b'{"private":"' + response_sentinel + b'"}'
                    )
            except BaseException as exc:
                server_errors.append(exc)
            finally:
                listener.close()

        server = threading.Thread(target=serve, daemon=True)
        server.start()
        activation, grant = _documents_for_runtime(_CodeOwnedRuntimeKey.DETERMINISTIC_PROBE)
        broker = CapabilityBroker()
        request = replace(
            _request(activation, grant),
            private_input={"private": request_sentinel.decode("ascii")},
        )
        catalog = code_owned_provider_catalog(gateway_policy=policy)
        selection = _execution_selection(
            request,
            broker,
            catalog=catalog,
            spec=runtime_spec(
                _CodeOwnedRuntimeKey.DETERMINISTIC_PROBE,
                gateway_policy=policy,
            ),
        )
        request = replace(
            request,
            provider_approval_id="provider_approval_loopback_indeterminate_01",
            provider_selection=selection,
        )
        authority = InMemoryProviderGovernanceAuthority()
        provider = OneShotProviderSupervisor.for_selection(
            selection,
            gateway_policy=policy,
            turn_timeout_ms=2_000,
        )

        with tempfile.TemporaryDirectory() as temporary:
            with AgentEventLog(temporary) as journal:
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
                authority.decide(
                    ProviderGovernanceDecision.create(
                        review=review,
                        reviewer_id="provider_reviewer_loopback_indeterminate_01",
                        outcome="approved",
                        expires_at_ms=5_000,
                    ),
                    expected_generation=0,
                    expected_review_hash=review.content_hash,
                )
                coordinator = AgentExecutionCoordinator(kernel=kernel, event_log=journal)
                with self.assertRaises(ProviderBoundaryIndeterminate) as caught:
                    coordinator.execute(request)
                replay = journal.replay_records(str(activation["execution_id"]))
                self.assertEqual("open", replay.state)
                self.assertIsNone(replay.receipt_bytes)
                public_records = b"".join(
                    (
                        replay.activation_bytes,
                        replay.grant_bytes,
                        *replay.event_bytes,
                    )
                )
                open_execution = journal.list_open(limit=1)[0]

            with AgentEventLog.recovery(temporary) as recovery:
                recovered = recovery.mark_recovery_required(
                    open_execution.execution_id,
                    expected_sequence=open_execution.next_sequence,
                    expected_previous_hash=open_execution.head_hash,
                    expected_generation=open_execution.generation,
                )
                self.assertEqual("recovery_required", recovered.state)
                self.assertIsNone(
                    recovery.replay_records(open_execution.execution_id).receipt_bytes
                )

            sqlite_bytes = b"".join(
                path.read_bytes() for path in Path(temporary).iterdir() if path.is_file()
            )

        server.join(2)
        self.assertEqual([], server_errors)
        self.assertEqual(1, accepted)
        self.assertEqual(1, len(received))
        self.assertNotIn(request_sentinel, received[0])
        self.assertNotIn(request_sentinel, public_records)
        self.assertNotIn(response_sentinel, public_records)
        self.assertNotIn(request_sentinel, sqlite_bytes)
        self.assertNotIn(response_sentinel, sqlite_bytes)
        self.assertEqual("provider_boundary_indeterminate", str(caught.exception))
        self.assertNotIn("RAW_LOOPBACK", str(caught.exception))
        self.assertEqual(1, provider.spawn_count)
        self.assertIsNone(provider.active_broker_pid)
        self.assertIsNone(provider.active_worker_pid)


if __name__ == "__main__":
    unittest.main()
