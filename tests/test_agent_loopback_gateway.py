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
from tests.test_agent_execution_kernel import _request, _usage
from tests.test_agent_provider_governance import _execution_selection
from tests.test_agent_runtime_dispatch import _documents_for_runtime
from worldforge.agent_harness import AgentEventLog, AgentExecutionCoordinator, CapabilityBroker
from worldforge.agent_harness import loopback_gateway as loopback_gateway_module
from worldforge.agent_harness import process_supervisor as process_supervisor_module
from worldforge.agent_harness import worker_protocol as worker_protocol_module
from worldforge.agent_harness.kernel import AgentExecutionKernel, KernelError
from worldforge.agent_harness.loopback_gateway import (
    LoopbackGatewayError,
    LoopbackGatewayIndeterminate,
    LoopbackGatewayPolicy,
    LoopbackGatewayStopped,
    LoopbackStepResult,
    execute_loopback_exchange,
    parse_loopback_http_response,
)
from worldforge.agent_harness.loopback_protocol import (
    LoopbackProtocolError,
    LoopbackProtocolSession,
    build_loopback_context_frame,
    build_loopback_request_frame,
    build_loopback_response_frame,
    parse_loopback_context_frame,
    parse_loopback_request_frame,
    parse_loopback_response_frame,
)
from worldforge.agent_harness.ports import (
    ProviderBoundaryControl,
    ProviderTurnRequest,
    ProviderTurnResult,
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
    runtime_entry,
    runtime_spec,
)

_RUNTIME = {
    "id": "worldforge_deterministic_probe_provider",
    "revision": 6,
    "content_hash": "1" * 64,
}
_NONCE = "2" * 64
_REQUEST_HASH = "3" * 64
_KEY = b"k" * 32


def _loopback_correlation(policy: LoopbackGatewayPolicy) -> dict[str, object]:
    return {
        "key": _KEY,
        "nonce": _NONCE,
        "runtime": _RUNTIME,
        "original_request_hash": _REQUEST_HASH,
        "gateway_policy_hash": policy.content_hash,
        "gateway_plan_hash": policy.plan_hash,
        "gateway_plan_count": policy.plan_count,
        "gateway_step_policy_hashes": tuple(step.content_hash for step in policy.ordered_steps),
    }


def _loopback_results(
    policy: LoopbackGatewayPolicy,
    request_body: object,
    response_bodies: tuple[object, object],
    *,
    challenges: tuple[str, str] = ("8" * 64, "9" * 64),
) -> tuple[LoopbackStepResult, LoopbackStepResult]:
    request_bytes = json.dumps(request_body, sort_keys=True, separators=(",", ":")).encode()
    results = []
    for index, response_body in enumerate(response_bodies):
        response_bytes = json.dumps(response_body, sort_keys=True, separators=(",", ":")).encode()
        body_bytes = request_bytes if index == 1 else b""
        results.append(
            LoopbackStepResult(
                index=index,
                step_policy_hash=policy.ordered_steps[index].content_hash,
                request_body_present=index == 1,
                request_body_hash=hashlib.sha256(body_bytes).hexdigest(),
                request_body_length=len(body_bytes),
                response_body=response_body,
                response_body_hash=hashlib.sha256(response_bytes).hexdigest(),
                response_body_length=len(response_bytes),
                response_challenge=challenges[index],
            )
        )
    return (results[0], results[1])


def _read_http_request(connection: socket.socket) -> bytes:
    raw = bytearray()
    while b"\r\n\r\n" not in raw:
        chunk = connection.recv(4096)
        if not chunk:
            raise EOFError
        raw.extend(chunk)
    headers, initial_body = bytes(raw).split(b"\r\n\r\n", 1)
    lengths = [
        int(line.split(b":", 1)[1])
        for line in headers.split(b"\r\n")
        if line.startswith(b"Content-Length:")
    ]
    length = lengths[0] if lengths else 0
    body = bytearray(initial_body)
    while len(body) < length:
        body.extend(connection.recv(length - len(body)))
    return headers + b"\r\n\r\n" + bytes(body)


def _send_json_response(connection: socket.socket, body: bytes) -> None:
    connection.sendall(
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
        + f"Content-Length: {len(body)}\r\n".encode("ascii")
        + b"Connection: close\r\n\r\n"
        + body
    )


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
    "format_version": 2,
    "gateway_plan_count": context["gateway_plan_count"],
    "gateway_plan_hash": context["gateway_plan_hash"],
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
        "input_tokens": {{
            "state": "derived", "source_kind": "code_owned_runtime", "value": 1,
            "policy_hash": "2e58a26fe511c1ceee6f5454c9e76b45fc99e9c9d1eff2798bc8bedabaa818e5",
            "unavailable_reason": None,
        }},
        "output_tokens": {{
            "state": "derived", "source_kind": "code_owned_runtime", "value": 1,
            "policy_hash": "2e58a26fe511c1ceee6f5454c9e76b45fc99e9c9d1eff2798bc8bedabaa818e5",
            "unavailable_reason": None,
        }},
        "cached_input_tokens": {{
            "state": "unavailable", "source_kind": "none", "value": None,
            "policy_hash": None, "unavailable_reason": "code_owned_policy_absent",
        }},
        "cost": {{
            "state": "unavailable", "source_kind": "none", "value": None,
            "currency": None, "policy_hash": None,
            "unavailable_reason": "parent_pricing_unavailable",
        }},
    }},
}}
final = authenticated({{
    "format": "world-forge.private.provider_turn_result",
    "format_version": 3,
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
        max_cost_minor_units=None,
        currency=spec.pricing_currency,
        max_duration_ms=2_000,
        deadline_ms=None,
        usage_policy_hash=spec.usage_policy_hash,
        pricing_policy_hash=spec.pricing_policy_hash,
        credential_revision_id=None,
    )


class LoopbackGatewayPolicyTests(unittest.TestCase):
    def test_policy_canonicalizes_exact_numeric_loopback_authorities(self) -> None:
        ipv4 = LoopbackGatewayPolicy.create("http://127.0.0.1:43123")
        ipv6 = LoopbackGatewayPolicy.create("http://[::1]:43124")

        self.assertEqual((2, "127.0.0.1", 43123), (ipv4.family, ipv4.host, ipv4.port))
        self.assertEqual((10, "::1", 43124), (ipv6.family, ipv6.host, ipv6.port))
        self.assertEqual("/worldforge/v1/ordered-loopback-probe", ipv4.path)
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
            **_loopback_correlation(policy),
        )
        parsed = parse_loopback_request_frame(
            request,
            **_loopback_correlation(policy),
        )
        self.assertEqual(body, parsed.body)
        self.assertEqual(
            len(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()),
            parsed.body_length,
        )

        response_body = ({"accepted": True, "step": 0}, {"accepted": True, "step": 1})
        response = build_loopback_response_frame(
            _loopback_results(policy, body, response_body),
            **_loopback_correlation(policy),
        )
        parsed_response = parse_loopback_response_frame(
            response,
            **_loopback_correlation(policy),
        )
        self.assertEqual(list(response_body), parsed_response.body)
        self.assertEqual(2, parsed_response.completed_count)
        self.assertRegex(parsed_response.exchange_hash or "", r"^[0-9a-f]{64}$")
        second_response = parse_loopback_response_frame(
            build_loopback_response_frame(
                _loopback_results(
                    policy,
                    body,
                    response_body,
                    challenges=("6" * 64, "7" * 64),
                ),
                **_loopback_correlation(policy),
            ),
            **_loopback_correlation(policy),
        )
        self.assertNotEqual(parsed_response.exchange_hash, second_response.exchange_hash)

    def test_gateway_final_requires_exact_response_bound_proof(self) -> None:
        result = ProviderTurnResult(
            private_output={"accepted": True},
            usage=_usage(input_tokens=1, output_tokens=1, cached_input_tokens=0),
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
            **_loopback_correlation(policy),
        )
        cases = (
            {"key": b"x" * 32},
            {"nonce": "0" * 64},
            {"runtime": {**_RUNTIME, "revision": 4}},
            {"original_request_hash": "0" * 64},
            {"gateway_policy_hash": "0" * 64},
        )
        defaults = _loopback_correlation(policy)
        for override in cases:
            with self.subTest(override=override), self.assertRaises(LoopbackProtocolError):
                parse_loopback_request_frame(frame, **{**defaults, **override})
        with self.assertRaises(LoopbackProtocolError):
            parse_loopback_request_frame(frame + b"x", **defaults)
        with self.assertRaises(LoopbackProtocolError):
            build_loopback_request_frame({"x": "y" * 8193}, **defaults)
        with self.assertRaises(LoopbackProtocolError):
            build_loopback_request_frame(("hostile", "tuple"), **defaults)

        session = LoopbackProtocolSession(**defaults)
        self.assertEqual({"probe": "one"}, session.accept_request(frame).body)
        with self.assertRaises(LoopbackProtocolError):
            session.accept_request(frame)
        response_bodies = ({"accepted": True, "step": 0}, {"accepted": True, "step": 1})
        response = session.build_response(
            _loopback_results(policy, {"probe": "one"}, response_bodies)
        )
        self.assertEqual(
            list(response_bodies),
            parse_loopback_response_frame(response, **defaults).body,
        )
        with self.assertRaises(LoopbackProtocolError):
            session.build_response(_loopback_results(policy, {"probe": "one"}, response_bodies))


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

    def test_accepts_crlf_header_delimiters_as_ordinary_json_body_whitespace(self) -> None:
        bodies = (
            (b"\r\n{}\r\n\r\n", {}),
            (b"[\r\n1,\r\n\r\n2\r\n]", [1, 2]),
            (b"\r\n\r\nnull\r\n\r\n", None),
        )
        for body, expected in bodies:
            response = (
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                + f"Content-Length: {len(body)}\r\n".encode("ascii")
                + b"Connection: close\r\n\r\n"
                + body
            )
            with self.subTest(body=body):
                self.assertEqual(expected, parse_loopback_http_response(response))

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
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
            b"Content-Type: application/json\r\n\r\n{}\r\n\r\nX",
            b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n"
            b"Content-Type: application/json\r\n\r\n{}\r\n\r\nX",
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
        streams = (self._Socket(response), self._Socket(response))
        bomb = mock.Mock(side_effect=AssertionError("forbidden helper"))
        with (
            mock.patch(
                "worldforge.agent_harness.loopback_gateway.socket.socket", side_effect=streams
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
        self.assertEqual(
            [{"accepted": True}, {"accepted": True}], [item.response_body for item in result]
        )
        self.assertTrue(all(stream.closed for stream in streams))
        self.assertTrue(all(b"Host: 127.0.0.1:43123\r\n" in stream.sent for stream in streams))
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
            return "execution_deadline_exceeded" if polls == 3 else None

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
                if stage == "pre_send_stop" and polls == 3:
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
            if polls == 3:
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
        self.assertGreaterEqual(stream.close_calls, 1)
        self.assertTrue(any("cleanup" in note for note in getattr(fatal, "__notes__", ())))

    def test_close_base_exception_is_preserved_with_bounded_cleanup_note(self) -> None:
        policy = LoopbackGatewayPolicy.create("http://127.0.0.1:43123")
        response_body = b'{"accepted":true}'
        response = (
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
            + f"Content-Length: {len(response_body)}\r\n".encode("ascii")
            + b"Connection: close\r\n\r\n"
            + response_body
        )

        class FatalClose(BaseException):
            pass

        fatal = FatalClose("RAW_CLOSE_BASE_SENTINEL")

        class FatalCloseSocket(self._Socket):
            def close(self) -> None:
                super().close()
                raise fatal

        stream = FatalCloseSocket(response)
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
            with self.assertRaises(FatalClose) as caught:
                execute_loopback_exchange(
                    policy,
                    {"probe": "fatal-close"},
                    boundary=lambda: None,
                    started=time.monotonic(),
                )
        self.assertIs(fatal, caught.exception)
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
        self.assertGreaterEqual(stream.close_calls, 1)

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
        listener.listen(2)
        port = listener.getsockname()[1]
        policy = LoopbackGatewayPolicy.create(f"http://127.0.0.1:{port}")
        received: list[bytes] = []
        finished = threading.Event()

        def serve() -> None:
            try:
                for index in range(2):
                    connection, _address = listener.accept()
                    with connection:
                        received.append(_read_http_request(connection))
                        response_body = (
                            f'{{"accepted":true,"source":"native-loopback","step":{index}}}'
                        ).encode("ascii")
                        _send_json_response(connection, response_body)
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
                transcript=(),
                tool_summaries=(),
                exposed_tools=(),
            ),
            boundary=ProviderBoundaryControl(lambda: None),
        )
        server.join(2)

        self.assertTrue(finished.is_set())
        self.assertEqual(
            [
                {"accepted": True, "source": "native-loopback", "step": 0},
                {"accepted": True, "source": "native-loopback", "step": 1},
            ],
            result.private_output["gateway_response"],
        )
        self.assertEqual(2, len(received))
        self.assertIn(b"GET /worldforge/v1/ordered-loopback-probe HTTP/1.1\r\n", received[0])
        self.assertIn(b"POST /worldforge/v1/ordered-loopback-probe HTTP/1.1\r\n", received[1])
        self.assertIsNone(supervisor.active_broker_pid)
        self.assertIsNone(supervisor.active_worker_pid)

    def test_native_probe_preserves_json_null_in_each_ordered_step(self) -> None:
        for response_values in ((None, {"step": 1}), ({"step": 0}, None), (None, None)):
            with self.subTest(response_values=response_values):
                listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                listener.bind(("127.0.0.1", 0))
                listener.listen(2)
                port = listener.getsockname()[1]
                policy = LoopbackGatewayPolicy.create(f"http://127.0.0.1:{port}")
                finished = threading.Event()

                def serve(
                    response_values: tuple[object, object] = response_values,
                    listener: socket.socket = listener,
                    finished: threading.Event = finished,
                ) -> None:
                    try:
                        for value in response_values:
                            connection, _address = listener.accept()
                            with connection:
                                _read_http_request(connection)
                                _send_json_response(
                                    connection,
                                    json.dumps(value, separators=(",", ":")).encode("utf-8"),
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
                        transcript=(),
                        tool_summaries=(),
                        exposed_tools=(),
                    ),
                    boundary=ProviderBoundaryControl(lambda: None),
                )
                server.join(2)

                self.assertTrue(finished.is_set())
                self.assertEqual(list(response_values), result.private_output["gateway_response"])
                self.assertIsNone(supervisor.active_broker_pid)
                self.assertIsNone(supervisor.active_worker_pid)

    def test_native_probe_accepts_json_whitespace_containing_header_delimiters(
        self,
    ) -> None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(2)
        policy = LoopbackGatewayPolicy.create(f"http://127.0.0.1:{listener.getsockname()[1]}")
        bodies = (b"\r\n{}\r\n\r\n", b"[\r\n1,\r\n\r\n2\r\n]")
        finished = threading.Event()

        def serve() -> None:
            try:
                for body in bodies:
                    connection, _address = listener.accept()
                    with connection:
                        _read_http_request(connection)
                        _send_json_response(connection, body)
            finally:
                listener.close()
                finished.set()

        server = threading.Thread(target=serve, daemon=True)
        server.start()
        supervisor = OneShotProviderSupervisor.for_selection(
            _loopback_selection(policy), gateway_policy=policy, turn_timeout_ms=2_000
        )
        result = supervisor.turn(
            ProviderTurnRequest(
                execution_id="exec_one",
                turn_index=0,
                private_input={"sentinel": "private-only"},
                transcript=(),
                tool_summaries=(),
                exposed_tools=(),
            ),
            boundary=ProviderBoundaryControl(lambda: None),
        )
        server.join(2)

        self.assertTrue(finished.is_set())
        self.assertEqual([{}, [1, 2]], result.private_output["gateway_response"])
        self.assertIsNone(supervisor.active_broker_pid)
        self.assertIsNone(supervisor.active_worker_pid)

    def test_early_worker_final_never_crosses_response_bound_acceptance(self) -> None:
        fork_context = multiprocessing.get_context("fork")
        for delay_seconds in (0.0, 0.02):
            with self.subTest(delay_seconds=delay_seconds):
                listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                listener.bind(("127.0.0.1", 0))
                listener.listen(2)
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
                        for index in range(2):
                            connection, _address = listener.accept()
                            accepted_count[0] += 1
                            with connection:
                                _read_http_request(connection)
                                if index == 1:
                                    time.sleep(0.1)
                                _send_json_response(
                                    connection,
                                    f'{{"accepted":true,"step":{index}}}'.encode("ascii"),
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
                self.assertEqual(2, accepted_count[0])
                self.assertEqual(1, provider.spawn_count)
                self.assertIsNone(provider.active_broker_pid)
                self.assertIsNone(provider.active_worker_pid)

    def test_private_turn_deadline_bounds_slow_post_send_gateway(self) -> None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(2)
        listener.settimeout(2)
        policy = LoopbackGatewayPolicy.create(f"http://127.0.0.1:{listener.getsockname()[1]}")
        accepted = 0

        def serve() -> None:
            nonlocal accepted
            try:
                connection, _address = listener.accept()
                accepted += 1
                with connection:
                    _read_http_request(connection)
                    time.sleep(1.0)
                    response = b'{"accepted":true}'
                    try:
                        _send_json_response(connection, response)
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
        listener.listen(2)
        policy = LoopbackGatewayPolicy.create(f"http://127.0.0.1:{listener.getsockname()[1]}")
        accepted = threading.Event()
        release = threading.Event()

        def serve() -> None:
            try:
                for index in range(2):
                    connection, _address = listener.accept()
                    with connection:
                        _read_http_request(connection)
                        if index == 0:
                            accepted.set()
                            release.wait(1)
                        _send_json_response(
                            connection,
                            f'{{"accepted":true,"step":{index}}}'.encode("ascii"),
                        )
            finally:
                listener.close()

        request = ProviderTurnRequest(
            execution_id="exec_one",
            turn_index=0,
            private_input={"probe": "concurrency"},
            transcript=(),
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
        listener.listen(2)
        listener.settimeout(2)
        port = listener.getsockname()[1]
        policy = LoopbackGatewayPolicy.create(f"http://127.0.0.1:{port}")
        accepted = 0

        def serve() -> None:
            nonlocal accepted
            try:
                for index in range(2):
                    connection, _address = listener.accept()
                    accepted += 1
                    with connection:
                        _read_http_request(connection)
                        _send_json_response(
                            connection,
                            f'{{"accepted":true,"step":{index}}}'.encode("ascii"),
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
        self.assertEqual(2, accepted)
        self.assertEqual(1, provider.spawn_count)

    def test_post_send_failure_leaves_private_open_prefix_for_offline_recovery(
        self,
    ) -> None:
        request_sentinel = b"RAW_LOOPBACK_REQUEST_SENTINEL"
        response_sentinel = b"RAW_LOOPBACK_RESPONSE_SENTINEL"
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(2)
        listener.settimeout(2)
        policy = LoopbackGatewayPolicy.create(f"http://127.0.0.1:{listener.getsockname()[1]}")
        accepted = 0
        received: list[bytes] = []
        server_errors: list[BaseException] = []

        def serve() -> None:
            nonlocal accepted
            try:
                for index in range(2):
                    connection, _address = listener.accept()
                    accepted += 1
                    with connection:
                        received.append(_read_http_request(connection))
                        if index == 0:
                            _send_json_response(connection, b'{"accepted":true,"step":0}')
                        else:
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
        self.assertEqual(2, accepted)
        self.assertEqual(2, len(received))
        self.assertNotIn(request_sentinel, received[0])
        self.assertNotIn(request_sentinel, received[1])
        self.assertIn(b'"private_input_hash":', received[1])
        self.assertNotIn(request_sentinel, public_records)
        self.assertNotIn(response_sentinel, public_records)
        self.assertNotIn(request_sentinel, sqlite_bytes)
        self.assertNotIn(response_sentinel, sqlite_bytes)
        self.assertEqual("provider_boundary_indeterminate", str(caught.exception))
        self.assertNotIn("RAW_LOOPBACK", str(caught.exception))
        self.assertEqual(1, provider.spawn_count)
        self.assertIsNone(provider.active_broker_pid)
        self.assertIsNone(provider.active_worker_pid)


class OrderedLoopbackPlanTddTests(unittest.TestCase):
    @staticmethod
    def _response(value: object, *, ordinary: bool = False) -> bytes:
        body = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=not ordinary,
            separators=(", ", ": ") if ordinary else (",", ":"),
        ).encode("utf-8")
        return (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/json\r\n"
            + f"Content-Length: {len(body)}\r\n".encode("ascii")
            + b"Connection: close\r\n\r\n"
            + body
        )

    def test_policy_freezes_exact_ordered_two_step_plan_and_aggregate_bounds(self) -> None:
        policy = LoopbackGatewayPolicy.create("http://127.0.0.1:43123")
        document = json.loads(policy.canonical_document)

        self.assertEqual(2, document["format_version"])
        self.assertEqual(2, policy.plan_count)
        self.assertEqual(
            [
                {
                    "body_present": False,
                    "index": 0,
                    "method": "GET",
                    "path": "/worldforge/v1/ordered-loopback-probe",
                    "request_body_limit": 0,
                    "response_body_limit": 64 * 1024,
                    "response_header_limit": 8 * 1024,
                },
                {
                    "body_present": True,
                    "index": 1,
                    "method": "POST",
                    "path": "/worldforge/v1/ordered-loopback-probe",
                    "request_body_limit": 8 * 1024,
                    "response_body_limit": 64 * 1024,
                    "response_header_limit": 8 * 1024,
                },
            ],
            document["ordered_steps"],
        )
        plan = document["ordered_plan"]
        self.assertEqual(document["ordered_steps"], plan["ordered_steps"])
        self.assertEqual(16 * 1024, plan["aggregate_bounds"]["response_header_bytes"])
        self.assertEqual(64 * 1024, plan["aggregate_bounds"]["response_body_bytes"])
        self.assertEqual(2_000, plan["deadline_policy"]["total_deadline_ms"])
        self.assertEqual(
            "process_supervisor_execute_after_authority_validation_and_turn_lock_before_scratch_or_process_setup",
            plan["deadline_policy"]["anchor_event"],
        )
        self.assertEqual("main_parent", plan["socket_lifecycle"]["owner"])
        self.assertTrue(plan["socket_lifecycle"]["fresh_socket_per_step"])
        self.assertTrue(plan["socket_lifecycle"]["close_before_next_step"])
        self.assertEqual("HTTP/1.1", plan["response_policy"]["http_version"])
        self.assertEqual(
            "first_crlf_crlf",
            plan["response_policy"]["header_terminator_rule"],
        )
        self.assertIn(
            "bare_lf_in_header_section",
            plan["response_policy"]["forbidden"],
        )
        self.assertEqual("reject_any_depth", plan["json_policy"]["duplicate_keys"])
        self.assertEqual(
            "immediately_before_first_send_syscall",
            plan["effect_policy"]["latch_point"],
        )
        self.assertEqual(
            hashlib.sha256(
                json.dumps(plan, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
            policy.plan_hash,
        )

    def test_each_semantic_cluster_mutation_propagates_through_selection_authority(self) -> None:
        baseline = LoopbackGatewayPolicy.create("http://127.0.0.1:43123")
        baseline_spec = runtime_spec(
            _CodeOwnedRuntimeKey.DETERMINISTIC_PROBE, gateway_policy=baseline
        )
        baseline_catalog = code_owned_provider_catalog(gateway_policy=baseline)
        baseline_selection = _loopback_selection(baseline)
        original = loopback_gateway_module._ordered_plan_values
        mutations = {
            "aggregate_bounds": lambda plan: plan["aggregate_bounds"].__setitem__(
                "response_header_bytes", 16 * 1024 - 1
            ),
            "deadline_policy": lambda plan: plan["deadline_policy"].__setitem__(
                "anchor_event", "loopback_exchange_entry"
            ),
            "effect_policy": lambda plan: plan["effect_policy"].__setitem__(
                "post_latch_failure", "closed"
            ),
            "json_policy": lambda plan: plan["json_policy"].__setitem__("maximum_depth", 63),
            "operation_policy": lambda plan: plan["operation_policy"].__setitem__(
                "query", "caller_selected"
            ),
            "request_policy": lambda plan: plan["request_policy"].__setitem__(
                "host_generation", "literal"
            ),
            "response_policy": lambda plan: plan["response_policy"].__setitem__("status", 201),
            "socket_lifecycle": lambda plan: plan["socket_lifecycle"].__setitem__("pooling", True),
        }

        for cluster, mutate in mutations.items():

            def changed(steps: object, mutate: object = mutate) -> dict[str, object]:
                plan = original(steps)  # type: ignore[arg-type]
                mutate(plan)  # type: ignore[operator]
                return plan

            with (
                self.subTest(cluster=cluster),
                mock.patch.object(loopback_gateway_module, "_ordered_plan_values", changed),
            ):
                policy = LoopbackGatewayPolicy.create("http://127.0.0.1:43123")
                spec = runtime_spec(_CodeOwnedRuntimeKey.DETERMINISTIC_PROBE, gateway_policy=policy)
                catalog = code_owned_provider_catalog(gateway_policy=policy)
                selection = _loopback_selection(policy)
                self.assertNotEqual(baseline.plan_hash, policy.plan_hash)
                self.assertNotEqual(baseline.content_hash, policy.content_hash)
                self.assertNotEqual(baseline_spec.content_hash, spec.content_hash)
                self.assertNotEqual(baseline_catalog.catalog_hash, catalog.catalog_hash)
                self.assertNotEqual(baseline_selection.content_hash, selection.content_hash)

    def test_embedded_worker_mirrors_the_exact_closed_host_plan_document(self) -> None:
        policy = LoopbackGatewayPolicy.create("http://127.0.0.1:43123")
        host_plan = json.loads(policy.canonical_document)["ordered_plan"]
        source = runtime_entry(_CodeOwnedRuntimeKey.DETERMINISTIC_PROBE).bootstrap_template
        prefix = source.split("def exact_context", 1)[0]
        namespace: dict[str, object] = {}
        exec(compile(prefix, "<ordered-plan-parity>", "exec"), namespace)

        self.assertEqual(host_plan, namespace["PLAN_DOCUMENT"])
        self.assertEqual(policy.plan_hash, namespace["PLAN_HASH"])

    def test_scratch_setup_delay_consumes_plan_budget_from_execute_entry(self) -> None:
        policy = LoopbackGatewayPolicy.create("http://127.0.0.1:43123")
        supervisor = process_supervisor_module.LinuxProcessSupervisor()
        now = [100.0]
        captured_started: list[float] = []

        def delayed_scratch(*_args: object, **_kwargs: object) -> str:
            now[0] = 102.001
            return scratch

        def exchange_after_setup(*_args: object, **kwargs: object) -> object:
            captured_started.append(kwargs["started"])
            return execute_loopback_exchange(
                policy,
                {"semantic": "payload"},
                boundary=lambda: None,
                started=kwargs["started"],
                private_deadline=kwargs["started"] + 3.0,
            )

        with tempfile.TemporaryDirectory() as root:
            scratch = str(Path(root) / "scratch")
            Path(scratch).mkdir()
            with (
                mock.patch(
                    "worldforge.agent_harness.process_supervisor.time.monotonic",
                    side_effect=lambda: now[0],
                ),
                mock.patch(
                    "worldforge.agent_harness.process_supervisor.tempfile.mkdtemp",
                    side_effect=delayed_scratch,
                ),
                mock.patch.object(
                    supervisor,
                    "_execute_with_scratch",
                    side_effect=exchange_after_setup,
                ),
                mock.patch(
                    "worldforge.agent_harness.loopback_gateway.socket.socket",
                    side_effect=AssertionError("deadline reset reached socket creation"),
                ) as socket_constructor,
            ):
                with self.assertRaises(ProviderBoundaryFailure):
                    supervisor.execute(
                        b"request",
                        worker_key=b"k" * 32,
                        boundary=ProviderBoundaryControl(lambda: None),
                        turn_timeout_ms=3_000,
                    )

        self.assertEqual([100.0], captured_started)
        socket_constructor.assert_not_called()

    def test_parent_sends_exact_get_then_post_on_fresh_closed_sockets(self) -> None:
        policy = LoopbackGatewayPolicy.create("http://127.0.0.1:43123")
        first = ParentOwnedExchangeTests._Socket(self._response({"step": 0}, ordinary=True))
        second = ParentOwnedExchangeTests._Socket(self._response({"step": 1}))
        created: list[ParentOwnedExchangeTests._Socket] = []

        def construct(*_args: object) -> ParentOwnedExchangeTests._Socket:
            stream = (first, second)[len(created)]
            if created:
                self.assertTrue(created[-1].closed)
            created.append(stream)
            return stream

        with (
            mock.patch(
                "worldforge.agent_harness.loopback_gateway.socket.socket",
                side_effect=construct,
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
            results = execute_loopback_exchange(
                policy,
                {"semantic": "payload"},
                boundary=lambda: None,
                started=time.monotonic(),
            )

        self.assertEqual(2, len(results))
        self.assertEqual(
            b"GET /worldforge/v1/ordered-loopback-probe HTTP/1.1\r\n",
            bytes(first.sent).split(b"\r\n", 1)[0] + b"\r\n",
        )
        self.assertNotIn(b"Content-Type:", first.sent)
        self.assertNotIn(b"Content-Length:", first.sent)
        self.assertTrue(bytes(first.sent).endswith(b"Connection: close\r\n\r\n"))
        self.assertIn(
            b"POST /worldforge/v1/ordered-loopback-probe HTTP/1.1\r\n",
            second.sent,
        )
        self.assertTrue(bytes(second.sent).endswith(b'\r\n\r\n{"semantic":"payload"}'))
        self.assertTrue(first.closed)
        self.assertTrue(second.closed)

    def test_http_json_is_canonicalized_after_ordinary_decode_and_rejects_hostile_numbers(
        self,
    ) -> None:
        ordinary = self._response({"z": 1, "a": [True, None]}, ordinary=True)
        self.assertEqual({"a": [True, None], "z": 1}, parse_loopback_http_response(ordinary))

        hostile_bodies = (
            b'{"a":1,"a":2}',
            b'{"x":NaN}',
            b'{"x":Infinity}',
            b'{"x":-Infinity}',
            b'{"x":1e999}',
            b'{"x":9007199254740992}',
            b"[" * 65 + b"0" + b"]" * 65,
        )
        for body in hostile_bodies:
            response = (
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                + f"Content-Length: {len(body)}\r\n".encode("ascii")
                + b"Connection: close\r\n\r\n"
                + body
            )
            with self.subTest(body=body), self.assertRaises(LoopbackGatewayError):
                parse_loopback_http_response(response)

    def test_first_send_attempt_latches_all_later_step_failures_indeterminate(self) -> None:
        policy = LoopbackGatewayPolicy.create("http://127.0.0.1:43123")
        first = ParentOwnedExchangeTests._Socket(self._response({"step": 0}))
        second = ParentOwnedExchangeTests._Socket(b"")
        second.connect_ex = lambda _address: errno.ECONNREFUSED  # type: ignore[method-assign]

        with (
            mock.patch(
                "worldforge.agent_harness.loopback_gateway.socket.socket",
                side_effect=(first, second),
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
                    {"semantic": "payload"},
                    boundary=lambda: None,
                    started=time.monotonic(),
                )
        self.assertTrue(first.closed)
        self.assertTrue(second.closed)

    def test_sideband_v2_binds_plan_order_steps_and_terminal_hmac_chain(self) -> None:
        policy = LoopbackGatewayPolicy.create("http://127.0.0.1:43123")
        correlation = {
            "key": _KEY,
            "nonce": _NONCE,
            "runtime": {**_RUNTIME, "revision": 6},
            "original_request_hash": _REQUEST_HASH,
            "gateway_policy_hash": policy.content_hash,
            "gateway_plan_hash": policy.plan_hash,
            "gateway_plan_count": policy.plan_count,
            "gateway_step_policy_hashes": tuple(step.content_hash for step in policy.ordered_steps),
        }
        context = build_loopback_context_frame(**correlation)
        parse_loopback_context_frame(context, **correlation)
        request = build_loopback_request_frame({"semantic": "payload"}, **correlation)
        parsed_request = parse_loopback_request_frame(request, **correlation)
        self.assertEqual({"semantic": "payload"}, parsed_request.body)

        results = tuple(
            LoopbackStepResult(
                index=index,
                step_policy_hash=policy.ordered_steps[index].content_hash,
                request_body_present=index == 1,
                request_body_hash=hashlib.sha256(
                    b'{"semantic":"payload"}' if index == 1 else b""
                ).hexdigest(),
                request_body_length=22 if index == 1 else 0,
                response_body={"step": index},
                response_body_hash=hashlib.sha256(
                    f'{{"step":{index}}}'.encode("ascii")
                ).hexdigest(),
                response_body_length=10,
                response_challenge=("8" if index == 0 else "9") * 64,
            )
            for index in range(2)
        )
        response = build_loopback_response_frame(results, **correlation)
        parsed = parse_loopback_response_frame(response, **correlation)
        self.assertEqual(2, parsed.completed_count)
        self.assertEqual((0, 1), tuple(step["index"] for step in parsed.steps))
        self.assertRegex(parsed.terminal_chain_hash or "", r"^[0-9a-f]{64}$")
        self.assertNotEqual(
            parsed.steps[0]["cumulative_chain_hash"],
            parsed.steps[1]["cumulative_chain_hash"],
        )

        document = json.loads(response[4:])
        document["steps"][1]["prior_chain_hash"] = "0" * 64
        unsigned = {name: value for name, value in document.items() if name != "mac"}
        document["mac"] = hmac.new(
            _KEY,
            json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode(),
            hashlib.sha256,
        ).hexdigest()
        payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
        with self.assertRaises(LoopbackProtocolError):
            parse_loopback_response_frame(len(payload).to_bytes(4, "big") + payload, **correlation)

    def test_sideband_rejects_v1_skip_reorder_surplus_duplicate_and_challenge_reuse(self) -> None:
        policy = LoopbackGatewayPolicy.create("http://127.0.0.1:43123")
        correlation = _loopback_correlation(policy)
        request_body = {"semantic": "payload"}
        results = _loopback_results(
            policy,
            request_body,
            ({"step": 0}, {"step": 1}),
        )
        response = build_loopback_response_frame(results, **correlation)
        original = json.loads(response[4:])

        def signed(document: dict[str, object]) -> bytes:
            unsigned = {name: value for name, value in document.items() if name != "mac"}
            document["mac"] = hmac.new(
                _KEY,
                json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode(),
                hashlib.sha256,
            ).hexdigest()
            payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
            return len(payload).to_bytes(4, "big") + payload

        hostile_documents = []
        for mutate in (
            lambda value: value.update(format_version=1),
            lambda value: value["steps"].pop(0),
            lambda value: value["steps"].reverse(),
            lambda value: value["steps"].append(copy.deepcopy(value["steps"][1])),
            lambda value: value["steps"].__setitem__(1, copy.deepcopy(value["steps"][0])),
            lambda value: value.update(completed_count=1),
            lambda value: value.update(terminal_chain_hash="0" * 64),
        ):
            candidate = copy.deepcopy(original)
            mutate(candidate)
            hostile_documents.append(candidate)
        for document in hostile_documents:
            with self.assertRaises(LoopbackProtocolError):
                parse_loopback_response_frame(signed(document), **correlation)

        with self.assertRaises(LoopbackProtocolError):
            build_loopback_response_frame(
                _loopback_results(
                    policy,
                    request_body,
                    ({"step": 0}, {"step": 1}),
                    challenges=("8" * 64, "8" * 64),
                ),
                **correlation,
            )
        with self.assertRaises(LoopbackProtocolError):
            parse_loopback_response_frame(
                response,
                **{**correlation, "gateway_plan_hash": "0" * 64},
            )

    def test_first_send_syscall_failure_and_cumulative_wire_overflow_are_indeterminate(
        self,
    ) -> None:
        policy = LoopbackGatewayPolicy.create("http://127.0.0.1:43123")

        send_failure = ParentOwnedExchangeTests._Socket(b"")
        send_failure.send = lambda _value: (_ for _ in ()).throw(  # type: ignore[method-assign]
            OSError("RAW_SEND_SENTINEL")
        )
        with (
            mock.patch(
                "worldforge.agent_harness.loopback_gateway.socket.socket",
                return_value=send_failure,
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
                    {"semantic": "payload"},
                    boundary=lambda: None,
                    started=time.monotonic(),
                )

        wire_body = b" " * (33 * 1024 - 2) + b"{}"
        wire_response = (
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
            + f"Content-Length: {len(wire_body)}\r\n".encode("ascii")
            + b"Connection: close\r\n\r\n"
            + wire_body
        )
        streams = (
            ParentOwnedExchangeTests._Socket(wire_response),
            ParentOwnedExchangeTests._Socket(wire_response),
        )
        with (
            mock.patch(
                "worldforge.agent_harness.loopback_gateway.socket.socket",
                side_effect=streams,
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
                    {"semantic": "payload"},
                    boundary=lambda: None,
                    started=time.monotonic(),
                )
        self.assertTrue(all(stream.closed for stream in streams))


if __name__ == "__main__":
    unittest.main()
