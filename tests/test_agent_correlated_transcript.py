from __future__ import annotations

import hashlib
import hmac
import json
import subprocess
import unittest
from unittest import mock

from tests.agent_harness_fakes import FakeProvider, FakeTool
from tests.test_agent_execution_kernel import _documents, _kernel, _request, _usage
from tests.test_agent_worker_supervisor import _turn_request
from worldforge.agent_harness import worker as worker_module
from worldforge.agent_harness import worker_protocol as worker_protocol_module
from worldforge.agent_harness.ports import (
    ProviderAssistantTranscriptItem,
    ProviderToolResultTranscriptItem,
    ProviderTurnRequest,
    ProviderTurnResult,
    ToolCall,
    ToolResult,
)
from worldforge.agent_harness.process_supervisor import fixed_worker_command
from worldforge.agent_harness.worker_protocol import (
    MAX_WORKER_REQUEST_BYTES,
    WorkerProtocolError,
    build_request_frame,
    build_result_frame,
    parse_request_frame,
    parse_result_frame,
)
from worldforge.agent_harness.worker_registry import _CodeOwnedRuntimeKey


def _authenticated_frame(document: dict[str, object], key: bytes) -> bytes:
    body = {name: value for name, value in document.items() if name != "mac"}
    encoded = json.dumps(
        body,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    document["mac"] = hmac.new(key, encoded, hashlib.sha256).hexdigest()
    payload = json.dumps(
        document,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return len(payload).to_bytes(4, "big") + payload


def _correlated_request(
    call_count: int,
    *,
    private_input: object = None,
) -> ProviderTurnRequest:
    calls = tuple(
        ToolCall("aa.bb", None, neutral_call_id=f"c{index}") for index in range(call_count)
    )
    transcript = (ProviderAssistantTranscriptItem(None, calls),) + tuple(
        ProviderToolResultTranscriptItem(call.neutral_call_id, call.tool_id, None) for call in calls
    )
    return ProviderTurnRequest(
        execution_id="execution_protocol_bound",
        turn_index=1,
        private_input=private_input,
        transcript=transcript,
    )


def _frame_with_129_calls(frame: bytes, key: bytes) -> bytes:
    document = json.loads(frame[4:])
    request = document["request"]
    request["transcript"][0]["tool_calls"].append(
        {
            "neutral_call_id": "c128",
            "tool_id": "aa.bb",
            "private_arguments": None,
        }
    )
    request["transcript"].append(
        {
            "role": "tool_result",
            "neutral_call_id": "c128",
            "tool_id": "aa.bb",
            "private_output": None,
        }
    )
    document["request_hash"] = hashlib.sha256(
        json.dumps(
            request,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()
    return _authenticated_frame(document, key)


class CorrelatedKernelTranscriptTests(unittest.TestCase):
    def test_assistant_precedes_ordered_results_and_distinct_ids_allow_identical_calls(
        self,
    ) -> None:
        activation, grant = _documents()
        first = ProviderTurnResult(
            private_output={"assistant": "PRIVATE_ASSISTANT"},
            usage=_usage(),
            tool_calls=(
                ToolCall(
                    "source.read",
                    {"path": "PRIVATE_PATH"},
                    neutral_call_id="neutral_call_01",
                ),
                ToolCall(
                    "source.read",
                    {"path": "PRIVATE_PATH"},
                    neutral_call_id="neutral_call_02",
                ),
            ),
            completed=False,
        )

        def finish(request: ProviderTurnRequest) -> ProviderTurnResult:
            self.assertEqual(
                (
                    ProviderAssistantTranscriptItem(
                        private_output={"assistant": "PRIVATE_ASSISTANT"},
                        tool_calls=first.tool_calls,
                    ),
                    ProviderToolResultTranscriptItem(
                        neutral_call_id="neutral_call_01",
                        tool_id="source.read",
                        private_output={"ordinal": 1},
                    ),
                    ProviderToolResultTranscriptItem(
                        neutral_call_id="neutral_call_02",
                        tool_id="source.read",
                        private_output={"ordinal": 2},
                    ),
                ),
                request.transcript,
            )
            return ProviderTurnResult("PRIVATE_FINAL", _usage(), completed=True)

        tool = FakeTool(
            "source.read",
            "tool.invoke",
            lambda call: ToolResult(
                {"ordinal": 1 if call.neutral_call_id == "neutral_call_01" else 2}
            ),
        )
        provider = FakeProvider((first, finish))
        result = _kernel(provider, tools=(tool,))[0].execute(_request(activation, grant))

        self.assertEqual("succeeded", result.outcome)
        self.assertEqual(
            ["neutral_call_01", "neutral_call_02"], [c.neutral_call_id for c in tool.calls]
        )
        durable = json.dumps({"events": result.events, "receipt": result.receipt})
        for private_value in (
            "PRIVATE_ASSISTANT",
            "PRIVATE_PATH",
            "neutral_call_01",
            "neutral_call_02",
            "ordinal",
        ):
            self.assertNotIn(private_value, durable)

    def test_reused_id_and_completed_with_calls_fail_batch_before_tool_effect(self) -> None:
        activation, grant = _documents()
        tool = FakeTool("source.read", "tool.invoke", ToolResult({"ok": True}))
        reused = FakeProvider(
            (
                ProviderTurnResult(
                    "first",
                    _usage(),
                    tool_calls=(ToolCall("source.read", {}, neutral_call_id="neutral_call_01"),),
                    completed=False,
                ),
                ProviderTurnResult(
                    "second",
                    _usage(),
                    tool_calls=(ToolCall("source.read", {}, neutral_call_id="neutral_call_01"),),
                    completed=False,
                ),
            )
        )
        result = _kernel(reused, tools=(tool,))[0].execute(_request(activation, grant))
        self.assertEqual(["duplicate_tool_call"], result.receipt["failure_codes"])
        self.assertEqual(1, len(tool.calls))

        completed_tool = FakeTool("source.read", "tool.invoke", ToolResult({"ok": True}))
        completed = FakeProvider(
            (
                ProviderTurnResult(
                    "done",
                    _usage(),
                    tool_calls=(ToolCall("source.read", {}, neutral_call_id="neutral_call_02"),),
                    completed=True,
                ),
            )
        )
        result = _kernel(completed, tools=(completed_tool,))[0].execute(_request(activation, grant))
        self.assertEqual(["provider_result_invalid"], result.receipt["failure_codes"])
        self.assertEqual([], completed_tool.calls)

    def test_cumulative_transcript_limit_fails_before_an_extra_provider_turn(self) -> None:
        activation, grant = _documents()
        provider = FakeProvider(
            (
                ProviderTurnResult("a" * 40_000, _usage(), completed=False),
                ProviderTurnResult("b" * 40_000, _usage(), completed=False),
                ProviderTurnResult("must_not_run", _usage(), completed=True),
            )
        )
        result = _kernel(provider)[0].execute(_request(activation, grant))
        self.assertEqual(["private_field_invalid"], result.receipt["failure_codes"])
        self.assertEqual(2, len(provider.requests))


class CorrelatedWorkerProtocolTests(unittest.TestCase):
    def test_host_builder_and_parser_enforce_exact_128_call_boundary(self) -> None:
        key = b"k" * 32
        nonce = "ab" * 32
        accepted = build_request_frame(_correlated_request(128), key=key, nonce=nonce)
        self.assertEqual(128, len(parse_request_frame(accepted, key=key).request.transcript) - 1)

        with self.assertRaisesRegex(WorkerProtocolError, "worker_protocol_request_invalid"):
            build_request_frame(_correlated_request(129), key=key, nonce=nonce)
        with self.assertRaisesRegex(WorkerProtocolError, "worker_protocol_request_invalid"):
            parse_request_frame(_frame_with_129_calls(accepted, key), key=key)

    def test_transcript_record_byte_and_outer_frame_limits_are_distinct(self) -> None:
        key = b"k" * 32
        nonce = "ab" * 32
        compact_records = tuple(ProviderAssistantTranscriptItem(None) for _index in range(256))
        accepted = ProviderTurnRequest(
            "execution_protocol_bound",
            1,
            None,
            compact_records,
        )
        self.assertEqual(
            compact_records,
            parse_request_frame(
                build_request_frame(accepted, key=key, nonce=nonce), key=key
            ).request.transcript,
        )

        for label, request in (
            (
                "record_count",
                ProviderTurnRequest(
                    "execution_protocol_bound",
                    1,
                    None,
                    compact_records + (ProviderAssistantTranscriptItem(None),),
                ),
            ),
            (
                "transcript_bytes",
                ProviderTurnRequest(
                    "execution_protocol_bound",
                    1,
                    None,
                    (ProviderAssistantTranscriptItem("x" * (64 * 1024)),),
                ),
            ),
        ):
            with (
                self.subTest(label=label),
                self.assertRaisesRegex(WorkerProtocolError, "worker_protocol_request_invalid"),
            ):
                build_request_frame(request, key=key, nonce=nonce)

        with self.assertRaisesRegex(WorkerProtocolError, "worker_protocol_oversized"):
            build_request_frame(
                ProviderTurnRequest(
                    "execution_protocol_bound",
                    1,
                    "x" * MAX_WORKER_REQUEST_BYTES,
                    (),
                ),
                key=key,
                nonce=nonce,
            )

    def test_exact_builtin_call_collection_and_shared_bound_are_active(self) -> None:
        class TupleSubclass(tuple):
            pass

        key = b"k" * 32
        nonce = "ab" * 32
        calls = _correlated_request(128).transcript[0].tool_calls
        hostile = ProviderTurnRequest(
            "execution_protocol_bound",
            1,
            None,
            (ProviderAssistantTranscriptItem(None, TupleSubclass(calls)),)
            + tuple(
                ProviderToolResultTranscriptItem(call.neutral_call_id, call.tool_id, None)
                for call in calls
            ),
        )
        with self.assertRaisesRegex(WorkerProtocolError, "worker_protocol_request_invalid"):
            build_request_frame(hostile, key=key, nonce=nonce)

        with mock.patch.object(
            worker_protocol_module,
            "MAX_PROVIDER_TOOL_CALLS_PER_TURN",
            127,
            create=True,
        ):
            with self.assertRaisesRegex(WorkerProtocolError, "worker_protocol_request_invalid"):
                build_request_frame(_correlated_request(128), key=key, nonce=nonce)

    def test_both_self_contained_workers_accept_128_and_reject_129_before_action(
        self,
    ) -> None:
        key = b"w" * 32
        nonce = "cd" * 32
        for runtime_key in _CodeOwnedRuntimeKey:
            with self.subTest(runtime=runtime_key.value, count=128):
                accepted = build_request_frame(
                    _correlated_request(128),
                    key=key,
                    nonce=nonce,
                    runtime_key=runtime_key,
                )
                completed = subprocess.run(
                    fixed_worker_command(runtime_key),
                    input=key + accepted,
                    capture_output=True,
                    timeout=2,
                    check=False,
                )
                self.assertEqual(0, completed.returncode)
                self.assertEqual(b"", completed.stderr)
                request_hash = json.loads(accepted[4:])["request_hash"]
                parse_result_frame(
                    completed.stdout,
                    key=key,
                    nonce=nonce,
                    request_hash=request_hash,
                    runtime_key=runtime_key,
                )

            with self.subTest(runtime=runtime_key.value, count=129):
                base = build_request_frame(
                    _correlated_request(
                        128,
                        private_input=(
                            {"__worldforge_conformance__": {"action": "stderr"}}
                            if runtime_key is _CodeOwnedRuntimeKey.CONFORMANCE
                            else None
                        ),
                    ),
                    key=key,
                    nonce=nonce,
                    runtime_key=runtime_key,
                )
                completed = subprocess.run(
                    fixed_worker_command(runtime_key),
                    input=key + _frame_with_129_calls(base, key),
                    capture_output=True,
                    timeout=2,
                    check=False,
                )
                self.assertEqual(70, completed.returncode)
                self.assertEqual(b"", completed.stdout)
                self.assertEqual(b"", completed.stderr)

    def test_embedded_bound_is_centralized_and_mutation_sensitive(self) -> None:
        token = worker_module._TOOL_CALL_LIMIT_TOKEN
        self.assertEqual(1, worker_module._WORKER_BOOTSTRAP_TEMPLATE.count(token))
        self.assertEqual(
            1,
            worker_module._DETERMINISTIC_PROBE_BOOTSTRAP_TEMPLATE_SOURCE.count(token),
        )
        for bootstrap in (
            worker_module.WORKER_BOOTSTRAP_TEMPLATE,
            worker_module._DETERMINISTIC_PROBE_BOOTSTRAP_TEMPLATE,
        ):
            self.assertNotIn(token, bootstrap)
            self.assertEqual(1, bootstrap.count("len(calls) > 128"))
        with mock.patch.object(
            worker_module, "MAX_PROVIDER_TOOL_CALLS_PER_TURN", True, create=True
        ):
            with self.assertRaises(RuntimeError):
                worker_module._embed_tool_call_limit(worker_module._WORKER_BOOTSTRAP_TEMPLATE)

    def test_v2_exact_discriminated_transcript_and_correlated_result_round_trip(self) -> None:
        call = ToolCall(
            "source.read",
            {"path": "PRIVATE_PATH"},
            neutral_call_id="neutral_call_01",
        )
        request = ProviderTurnRequest(
            execution_id="execution_protocol_01",
            turn_index=1,
            private_input={"secret": "PRIVATE_INPUT"},
            transcript=(
                ProviderAssistantTranscriptItem("PRIVATE_ASSISTANT", (call,)),
                ProviderToolResultTranscriptItem(
                    "neutral_call_01", "source.read", {"text": "PRIVATE_RESULT"}
                ),
            ),
        )
        key = b"k" * 32
        nonce = "ab" * 32
        frame = build_request_frame(request, key=key, nonce=nonce)
        document = json.loads(frame[4:])
        self.assertEqual(3, document["format_version"])
        self.assertEqual(
            ["assistant", "tool_result"],
            [item["role"] for item in document["request"]["transcript"]],
        )
        self.assertEqual(request, parse_request_frame(frame, key=key).request)

        result = ProviderTurnResult(
            "next",
            _usage(),
            tool_calls=(call,),
            completed=False,
        )
        result_frame = build_result_frame(
            result,
            key=key,
            nonce=nonce,
            request_hash=document["request_hash"],
        )
        self.assertEqual(
            result,
            parse_result_frame(
                result_frame,
                key=key,
                nonce=nonce,
                request_hash=document["request_hash"],
            ),
        )

    def test_v1_untyped_or_malformed_transcript_fails_closed_under_valid_hmac(self) -> None:
        key = b"k" * 32
        request = _turn_request({"value": 1})
        frame = build_request_frame(request, key=key, nonce="ab" * 32)

        cases = {
            "v1": lambda document: document.__setitem__("format_version", 1),
            "untyped": lambda document: document["request"].__setitem__("transcript", [1]),
            "orphan": lambda document: document["request"].__setitem__(
                "transcript",
                [
                    {
                        "role": "tool_result",
                        "neutral_call_id": "neutral_call_01",
                        "tool_id": "source.read",
                        "private_output": {},
                    }
                ],
            ),
            "unknown_role": lambda document: document["request"].__setitem__(
                "transcript", [{"role": "vendor", "private_output": {}, "tool_calls": []}]
            ),
            "missing_result": lambda document: document["request"].__setitem__(
                "transcript",
                [
                    {
                        "role": "assistant",
                        "private_output": {},
                        "tool_calls": [
                            {
                                "neutral_call_id": "neutral_call_01",
                                "tool_id": "source.read",
                                "private_arguments": {},
                            }
                        ],
                    }
                ],
            ),
            "mismatched_id": lambda document: document["request"].__setitem__(
                "transcript",
                [
                    {
                        "role": "assistant",
                        "private_output": {},
                        "tool_calls": [
                            {
                                "neutral_call_id": "neutral_call_01",
                                "tool_id": "source.read",
                                "private_arguments": {},
                            }
                        ],
                    },
                    {
                        "role": "tool_result",
                        "neutral_call_id": "neutral_call_02",
                        "tool_id": "source.read",
                        "private_output": {},
                    },
                ],
            ),
            "mismatched_tool": lambda document: document["request"].__setitem__(
                "transcript",
                [
                    {
                        "role": "assistant",
                        "private_output": {},
                        "tool_calls": [
                            {
                                "neutral_call_id": "neutral_call_01",
                                "tool_id": "source.read",
                                "private_arguments": {},
                            }
                        ],
                    },
                    {
                        "role": "tool_result",
                        "neutral_call_id": "neutral_call_01",
                        "tool_id": "world.validate",
                        "private_output": {},
                    },
                ],
            ),
            "reordered": lambda document: document["request"].__setitem__(
                "transcript",
                [
                    {
                        "role": "assistant",
                        "private_output": {},
                        "tool_calls": [
                            {
                                "neutral_call_id": "neutral_call_01",
                                "tool_id": "source.read",
                                "private_arguments": {},
                            },
                            {
                                "neutral_call_id": "neutral_call_02",
                                "tool_id": "world.validate",
                                "private_arguments": {},
                            },
                        ],
                    },
                    {
                        "role": "tool_result",
                        "neutral_call_id": "neutral_call_02",
                        "tool_id": "world.validate",
                        "private_output": {},
                    },
                    {
                        "role": "tool_result",
                        "neutral_call_id": "neutral_call_01",
                        "tool_id": "source.read",
                        "private_output": {},
                    },
                ],
            ),
        }
        for name, mutate in cases.items():
            with self.subTest(name=name):
                document = json.loads(frame[4:])
                mutate(document)
                document["request_hash"] = hashlib.sha256(
                    json.dumps(
                        document["request"],
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                        allow_nan=False,
                    ).encode("utf-8")
                ).hexdigest()
                with self.assertRaises(WorkerProtocolError):
                    parse_request_frame(_authenticated_frame(document, key), key=key)

    def test_result_missing_or_hostile_neutral_call_id_fails_closed(self) -> None:
        key = b"k" * 32
        nonce = "ab" * 32
        request_hash = "cd" * 32
        result = ProviderTurnResult(
            "next",
            _usage(),
            tool_calls=(ToolCall("source.read", {}, neutral_call_id="neutral_call_01"),),
            completed=False,
        )
        frame = build_result_frame(
            result,
            key=key,
            nonce=nonce,
            request_hash=request_hash,
        )
        for value in (None, "contains space", "x" * 65, 1):
            with self.subTest(value=value):
                document = json.loads(frame[4:])
                if value is None:
                    del document["result"]["tool_calls"][0]["neutral_call_id"]
                else:
                    document["result"]["tool_calls"][0]["neutral_call_id"] = value
                document["result_hash"] = hashlib.sha256(
                    json.dumps(
                        document["result"],
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                        allow_nan=False,
                    ).encode("utf-8")
                ).hexdigest()
                with self.assertRaisesRegex(WorkerProtocolError, "worker_protocol_result_invalid"):
                    parse_result_frame(
                        _authenticated_frame(document, key),
                        key=key,
                        nonce=nonce,
                        request_hash=request_hash,
                    )
