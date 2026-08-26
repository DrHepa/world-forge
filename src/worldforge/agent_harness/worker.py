"""Code-owned bootstrap for the fixed private conformance worker."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from .usage import code_owned_usage_policy_hash
from .worker_limits import MAX_PROVIDER_TOOL_CALLS_PER_TURN

# This source is deliberately self-contained.  ``-I -S`` prevents the child
# from importing the checkout, so the supervisor passes no module or path.
_CONFORMANCE_RUNTIME_ID = "worldforge_conformance_provider"
_CONFORMANCE_RUNTIME_REVISION = 4
_RUNTIME_ID_TOKEN = "__WORLD_FORGE_RUNTIME_ID__"
_RUNTIME_REVISION_TOKEN = "__WORLD_FORGE_RUNTIME_REVISION__"
_TOOL_CALL_LIMIT_TOKEN = "__WORLD_FORGE_MAX_TOOL_CALLS_PER_TURN__"
RUNTIME_CONTENT_HASH_TOKEN = "__WORLD_FORGE_RUNTIME_CONTENT_HASH__"
_USAGE_POLICY_HASH_TOKEN = "__WORLD_FORGE_USAGE_POLICY_HASH__"


def _embed_tool_call_limit(source: str) -> str:
    if (
        type(source) is not str
        or source.count(_TOOL_CALL_LIMIT_TOKEN) != 1
        or type(MAX_PROVIDER_TOOL_CALLS_PER_TURN) is not int
        or MAX_PROVIDER_TOOL_CALLS_PER_TURN < 1
    ):
        raise RuntimeError("provider_worker_tool_call_limit_invalid")
    return source.replace(
        _TOOL_CALL_LIMIT_TOKEN,
        str(MAX_PROVIDER_TOOL_CALLS_PER_TURN),
    )


_WORKER_BOOTSTRAP_TEMPLATE = r"""
import hashlib
import hmac
import json
import math
import os
import signal
import struct
import sys
import time

MAX_REQUEST = 256 * 1024
MAX_RESPONSE = 32 * 1024 * 1024
RUNTIME = {
    "id": "__WORLD_FORGE_RUNTIME_ID__",
    "revision": __WORLD_FORGE_RUNTIME_REVISION__,
    "content_hash": "__WORLD_FORGE_RUNTIME_CONTENT_HASH__",
}
USAGE_POLICY_HASH = "__WORLD_FORGE_USAGE_POLICY_HASH__"
MAX_DEPTH = 64
MAX_TRANSCRIPT = 256
MAX_SAFE_INTEGER = (1 << 53) - 1
CAPABILITIES = frozenset({
    "artifact.propose", "artifact.read", "memory.propose",
    "memory.read", "project.read", "tool.invoke",
})

class DuplicateKey(Exception):
    pass

def pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise DuplicateKey()
        result[key] = value
    return result

def canonical(value):
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")

def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()

def mac(document, key):
    body = {name: value for name, value in document.items() if name != "mac"}
    return hmac.new(key, canonical(body), hashlib.sha256).hexdigest()

def read_exact(count):
    chunks = []
    remaining = count
    while remaining:
        value = os.read(0, remaining)
        if not value:
            raise EOFError()
        chunks.append(value)
        remaining -= len(value)
    return b"".join(chunks)

def require_eof():
    while True:
        try:
            trailing = os.read(0, 1)
            break
        except InterruptedError:
            continue
    if trailing:
        raise ValueError()

def exact_sha256(value):
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )

def exact_identifier(value):
    return (
        type(value) is str
        and 2 <= len(value) <= 64
        and value[0] in "abcdefghijklmnopqrstuvwxyz"
        and all(character in "abcdefghijklmnopqrstuvwxyz0123456789_" for character in value[1:])
    )

def exact_tool_id(value):
    if type(value) is not str or len(value) > 1024:
        return False
    parts = value.split(".")
    return len(parts) >= 2 and all(exact_identifier(part) for part in parts)

def exact_neutral_call_id(value):
    return (
        type(value) is str
        and 1 <= len(value) <= 64
        and value[0].isascii()
        and value[0].isalnum()
        and all(
            character.isascii() and (character.isalnum() or character in "._:-")
            for character in value
        )
    )

def exact_json(value, depth=1, max_depth=MAX_DEPTH):
    if depth > max_depth:
        return False
    if value is None or type(value) in {bool, str}:
        return True
    if type(value) is int:
        return abs(value) <= MAX_SAFE_INTEGER
    if type(value) is float:
        return math.isfinite(value)
    if type(value) is list:
        return all(exact_json(item, depth + 1, max_depth) for item in value)
    if type(value) is dict:
        return all(
            type(key) is str and exact_json(item, depth + 1, max_depth)
            for key, item in value.items()
        )
    return False

def exact_transcript(value):
    if type(value) is not list or len(value) > MAX_TRANSCRIPT:
        return False
    if len(canonical(value)) > 64 * 1024:
        return False
    seen = set()
    index = 0
    while index < len(value):
        assistant = value[index]
        if type(assistant) is not dict or set(assistant) != {
            "role", "private_output", "tool_calls"
        }:
            return False
        if assistant["role"] != "assistant" or not exact_json(assistant["private_output"]):
            return False
        calls = assistant["tool_calls"]
        if type(calls) is not list or len(calls) > __WORLD_FORGE_MAX_TOOL_CALLS_PER_TURN__:
            return False
        index += 1
        for call in calls:
            if type(call) is not dict or set(call) != {
                "neutral_call_id", "tool_id", "private_arguments"
            }:
                return False
            call_id = call["neutral_call_id"]
            if (
                not exact_neutral_call_id(call_id)
                or call_id in seen
                or not exact_tool_id(call["tool_id"])
                or not exact_json(call["private_arguments"])
            ):
                return False
            seen.add(call_id)
            if index >= len(value):
                return False
            result = value[index]
            if type(result) is not dict or set(result) != {
                "role", "neutral_call_id", "tool_id", "private_output"
            }:
                return False
            if (
                result["role"] != "tool_result"
                or result["neutral_call_id"] != call_id
                or result["tool_id"] != call["tool_id"]
                or not exact_json(result["private_output"])
            ):
                return False
            index += 1
    return True

def exact_request(value):
    if type(value) is not dict or set(value) != {
        "execution_id", "turn_index", "private_input", "transcript",
        "tool_summaries", "exposed_tools"
    }:
        return False
    transcript = value["transcript"]
    summaries = value["tool_summaries"]
    definitions = value["exposed_tools"]
    if type(summaries) is not list or len(summaries) > 128:
        return False
    summary_snapshots = {}
    for item in summaries:
        if type(item) is not dict or set(item) != {"tool_id", "summary", "descriptor_hash"}:
            return False
        tool_id = item["tool_id"]
        summary = item["summary"]
        if (
            not exact_tool_id(tool_id)
            or tool_id in summary_snapshots
            or type(summary) is not str
            or not summary
            or len(summary.encode("utf-8")) > 1024
            or any(ord(character) < 32 or ord(character) == 127 for character in summary)
            or not exact_sha256(item["descriptor_hash"])
        ):
            return False
        summary_snapshots[tool_id] = (item["descriptor_hash"], summary)
    if type(definitions) is not list or len(definitions) > 128:
        return False
    definition_ids = set()
    for item in definitions:
        if type(item) is not dict or set(item) != {
            "tool_id", "required_capability_id", "summary", "input_schema", "descriptor_hash"
        }:
            return False
        tool_id = item["tool_id"]
        if (
            not exact_tool_id(tool_id)
            or tool_id in definition_ids
            or not exact_tool_id(item["required_capability_id"])
            or item["required_capability_id"] not in CAPABILITIES
            or type(item["summary"]) is not str
            or type(item["input_schema"]) is not dict
            or not exact_json(item["input_schema"], max_depth=32)
            or len(canonical(item["input_schema"])) > 16 * 1024
            or summary_snapshots.get(tool_id)
            != (item["descriptor_hash"], item["summary"])
            or digest({
                "tool_id": tool_id,
                "required_capability_id": item["required_capability_id"],
                "summary": item["summary"],
                "input_schema": item["input_schema"],
            }) != item["descriptor_hash"]
        ):
            return False
        definition_ids.add(tool_id)
    return (
        exact_identifier(value["execution_id"])
        and type(value["turn_index"]) is int
        and 0 <= value["turn_index"] <= 64
        and exact_json(value["private_input"])
        and exact_transcript(transcript)
    )

def exact_runtime(value):
    return (
        type(value) is dict
        and set(value) == {"id", "revision", "content_hash"}
        and type(value["id"]) is str
        and value["id"] == RUNTIME["id"]
        and type(value["revision"]) is int
        and value["revision"] == RUNTIME["revision"]
        and exact_sha256(value["content_hash"])
        and value["content_hash"] == RUNTIME["content_hash"]
    )

def write_all(descriptor, payload):
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError()
        view = view[written:]

def read_request(key):
    size = struct.unpack(">I", read_exact(4))[0]
    if size > MAX_REQUEST:
        raise ValueError()
    raw = read_exact(size)
    require_eof()
    document = json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=pairs,
        parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
    )
    if canonical(document) != raw:
        raise ValueError()
    expected = {
        "format", "format_version", "mac", "nonce", "request", "request_hash", "runtime"
    }
    if set(document) != expected:
        raise ValueError()
    if document["format"] != "world-forge.private.provider_turn_request":
        raise ValueError()
    if (
        type(document["format_version"]) is not int
        or document["format_version"] != 3
        or not exact_sha256(document["nonce"])
        or not exact_runtime(document["runtime"])
    ):
        raise ValueError()
    if not exact_sha256(document["mac"]) or not hmac.compare_digest(
        document["mac"], mac(document, key)
    ):
        raise ValueError()
    if not exact_sha256(document["request_hash"]) or not hmac.compare_digest(
        document["request_hash"], digest(document["request"])
    ):
        raise ValueError()
    if not exact_request(document["request"]):
        raise ValueError()
    return document

def result_document(request_document, result):
    document = {
        "format": "world-forge.private.provider_turn_result",
        "format_version": 3,
        "nonce": request_document["nonce"],
        "request_hash": request_document["request_hash"],
        "result": result,
        "result_hash": digest(result),
        "runtime": RUNTIME,
    }
    return document

def emit(document, key, action):
    document["mac"] = mac(document, key)
    if action == "wrong_mac":
        document["mac"] = "0" * 64
    elif action == "wrong_nonce":
        document["nonce"] = "0" * 64
        document["mac"] = mac(document, key)
    elif action == "wrong_hash":
        document["result_hash"] = "0" * 64
        document["mac"] = mac(document, key)
    elif action == "wrong_request_hash":
        document["request_hash"] = "0" * 64
        document["mac"] = mac(document, key)
    elif action == "wrong_runtime":
        document["runtime"] = dict(RUNTIME)
        document["runtime"]["content_hash"] = "0" * 64
        document["mac"] = mac(document, key)
    raw = canonical(document)
    if action == "noncanonical":
        raw = json.dumps(document, ensure_ascii=False, sort_keys=True).encode("utf-8")
    elif action == "duplicate_key":
        raw = raw.replace(b'{"format":', b'{"format":"duplicate","format":', 1)
    frame = struct.pack(">I", len(raw)) + raw
    if action == "trailing":
        frame += b"x"
    elif action == "second_frame":
        frame += frame
    write_all(1, frame)

def usage(config):
    return config.get("usage", {
        "input_tokens": {
            "state": "derived", "source_kind": "code_owned_runtime", "value": 1,
            "policy_hash": USAGE_POLICY_HASH, "unavailable_reason": None,
        },
        "output_tokens": {
            "state": "derived", "source_kind": "code_owned_runtime", "value": 1,
            "policy_hash": USAGE_POLICY_HASH, "unavailable_reason": None,
        },
        "cached_input_tokens": {
            "state": "unavailable", "source_kind": "none", "value": None,
            "policy_hash": None, "unavailable_reason": "code_owned_policy_absent",
        },
        "cost": {
            "state": "unavailable", "source_kind": "none", "value": None,
            "currency": None, "policy_hash": None,
            "unavailable_reason": "parent_pricing_unavailable",
        },
    })

def spawn_tree():
    read_fd, write_fd = os.pipe()
    first = os.fork()
    if first == 0:
        os.close(read_fd)
        os.setsid()
        second = os.fork()
        if second == 0:
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            signal.signal(signal.SIGHUP, signal.SIG_IGN)
            time.sleep(30)
            os._exit(0)
        os.write(write_fd, (str(os.getpid()) + "," + str(second)).encode("ascii"))
        os.close(write_fd)
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGHUP, signal.SIG_IGN)
        time.sleep(30)
        os._exit(0)
    os.close(write_fd)
    payload = os.read(read_fd, 128)
    os.close(read_fd)
    values = [int(value) for value in payload.decode("ascii").split(",")]
    return values

def audit_environment():
    before = os.listdir(".") == []
    descriptors = []
    if os.path.isdir("/proc/self/fd"):
        numbers = sorted(
            int(name) for name in os.listdir("/proc/self/fd") if name.isdigit()
        )
    else:
        numbers = range(2048)
    for number in numbers:
        try:
            os.fstat(number)
        except OSError:
            continue
        descriptors.append(number)
    def importable(name):
        try:
            __import__(name)
        except BaseException:
            return False
        return True
    telemetry_names = (
        "DO_NOT_TRACK", "HF_HUB_DISABLE_TELEMETRY", "OPENAI_DISABLE_TELEMETRY",
        "ANTHROPIC_DISABLE_TELEMETRY",
    )
    return {
        "scratch_empty": before,
        "open_fds": descriptors,
        "environment_names": sorted(os.environ),
        "dont_write_bytecode": sys.dont_write_bytecode,
        "telemetry": {name: os.environ.get(name) for name in telemetry_names},
        "worldforge_importable": importable("worldforge.studio"),
        "isoworld_importable": importable("isoworld"),
    }

def main():
    if len(sys.argv) != 1:
        raise ValueError()
    key = read_exact(32)
    request_document = read_request(key)
    private_input = request_document["request"]["private_input"]
    config = {}
    if type(private_input) is dict:
        candidate = private_input.get("__worldforge_conformance__", {})
        if type(candidate) is dict:
            config = candidate
    turn_plan = config.get("turn_plan")
    if turn_plan is not None:
        if (
            type(turn_plan) is not list
            or len(turn_plan) > 64
            or not all(type(item) is dict and exact_json(item) for item in turn_plan)
        ):
            raise ValueError()
        turn_index = request_document["request"]["turn_index"]
        config = turn_plan[turn_index] if turn_index < len(turn_plan) else {}
    action = config.get("action", "echo")
    if action == "crash":
        os._exit(17)
    if action == "stderr":
        os.write(2, b"conformance runtime stderr")
    if action == "output_overflow":
        os.write(1, struct.pack(">I", MAX_RESPONSE + 1))
        return
    if action == "sleep":
        time.sleep(config.get("milliseconds", 1000) / 1000)
    descendant_pids = []
    if action == "spawn_tree":
        descendant_pids = spawn_tree()
        if config.get("hold_milliseconds"):
            time.sleep(config["hold_milliseconds"] / 1000)
    if action == "audit_environment":
        private_output = audit_environment()
    else:
        private_output = {"payload": config.get("payload")}
        if config.get("include_transcript"):
            private_output["transcript"] = request_document["request"]["transcript"]
        if config.get("include_worker_pid"):
            private_output["worker_pid"] = os.getpid()
        if descendant_pids:
            private_output["worker_pid"] = os.getpid()
            private_output["descendant_pids"] = descendant_pids
    result = {
        "private_output": private_output,
        "usage": usage(config),
        "tool_calls": config.get("tool_calls", []),
        "artifact_proposals": config.get("artifact_proposals", []),
        "memory_proposals": config.get("memory_proposals", []),
        "tool_exposure_requests": config.get("tool_exposure_requests", []),
        "completed": config.get("completed", True),
    }
    document = result_document(request_document, result)
    emit(document, key, action)

try:
    main()
except BaseException:
    os._exit(70)
"""

WORKER_BOOTSTRAP_TEMPLATE = _embed_tool_call_limit(
    _WORKER_BOOTSTRAP_TEMPLATE.replace(
        _RUNTIME_ID_TOKEN,
        _CONFORMANCE_RUNTIME_ID,
    )
    .replace(
        _RUNTIME_REVISION_TOKEN,
        str(_CONFORMANCE_RUNTIME_REVISION),
    )
    .replace(
        _USAGE_POLICY_HASH_TOKEN,
        code_owned_usage_policy_hash(_CONFORMANCE_RUNTIME_ID),
    )
)
_CONFORMANCE_RUNTIME_HASH = hashlib.sha256(WORKER_BOOTSTRAP_TEMPLATE.encode("utf-8")).hexdigest()
WORKER_BOOTSTRAP = WORKER_BOOTSTRAP_TEMPLATE.replace(
    RUNTIME_CONTENT_HASH_TOKEN,
    _CONFORMANCE_RUNTIME_HASH,
)


_DETERMINISTIC_PROBE_RUNTIME_ID = "worldforge_deterministic_probe_provider"
_DETERMINISTIC_PROBE_RUNTIME_REVISION = 5
_DETERMINISTIC_PROBE_BOOTSTRAP_TEMPLATE_SOURCE = r"""
import hashlib
import hmac
import json
import math
import os
import struct
import sys

MAX_REQUEST = 256 * 1024
MAX_GATEWAY_REQUEST = 16 * 1024
MAX_GATEWAY_RESPONSE = 80 * 1024
MAX_GATEWAY_REQUEST_BODY = 8 * 1024
MAX_GATEWAY_RESPONSE_BODY = 64 * 1024
RUNTIME = {
    "id": "worldforge_deterministic_probe_provider",
    "revision": 5,
    "content_hash": "__WORLD_FORGE_RUNTIME_CONTENT_HASH__",
}
USAGE_POLICY_HASH = "__WORLD_FORGE_USAGE_POLICY_HASH__"
MAX_DEPTH = 64
MAX_TRANSCRIPT = 256
MAX_SAFE_INTEGER = (1 << 53) - 1
CAPABILITIES = frozenset({
    "artifact.propose", "artifact.read", "memory.propose",
    "memory.read", "project.read", "tool.invoke",
})

class DuplicateKey(Exception):
    pass

def pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise DuplicateKey()
        result[key] = value
    return result

def canonical(value):
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")

def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()

def mac(document, key):
    body = {name: value for name, value in document.items() if name != "mac"}
    return hmac.new(key, canonical(body), hashlib.sha256).hexdigest()

def read_exact(count):
    chunks = []
    remaining = count
    while remaining:
        value = os.read(0, remaining)
        if not value:
            raise EOFError()
        chunks.append(value)
        remaining -= len(value)
    return b"".join(chunks)

def require_eof():
    while True:
        try:
            trailing = os.read(0, 1)
            break
        except InterruptedError:
            continue
    if trailing:
        raise ValueError()

def write_all(descriptor, payload):
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError()
        view = view[written:]

def exact_sha256(value):
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )

def exact_identifier(value):
    return (
        type(value) is str
        and 2 <= len(value) <= 64
        and value[0] in "abcdefghijklmnopqrstuvwxyz"
        and all(character in "abcdefghijklmnopqrstuvwxyz0123456789_" for character in value[1:])
    )

def exact_tool_id(value):
    if type(value) is not str or len(value) > 1024:
        return False
    parts = value.split(".")
    return len(parts) >= 2 and all(exact_identifier(part) for part in parts)

def exact_neutral_call_id(value):
    return (
        type(value) is str
        and 1 <= len(value) <= 64
        and value[0].isascii()
        and value[0].isalnum()
        and all(
            character.isascii() and (character.isalnum() or character in "._:-")
            for character in value
        )
    )

def exact_json(value, depth=1, max_depth=MAX_DEPTH):
    if depth > max_depth:
        return False
    if value is None or type(value) in {bool, str}:
        return True
    if type(value) is int:
        return abs(value) <= MAX_SAFE_INTEGER
    if type(value) is float:
        return math.isfinite(value)
    if type(value) is list:
        return all(exact_json(item, depth + 1, max_depth) for item in value)
    if type(value) is dict:
        return all(
            type(key) is str and exact_json(item, depth + 1, max_depth)
            for key, item in value.items()
        )
    return False

def exact_transcript(value):
    if type(value) is not list or len(value) > MAX_TRANSCRIPT:
        return False
    if len(canonical(value)) > 64 * 1024:
        return False
    seen = set()
    index = 0
    while index < len(value):
        assistant = value[index]
        if type(assistant) is not dict or set(assistant) != {
            "role", "private_output", "tool_calls"
        }:
            return False
        if assistant["role"] != "assistant" or not exact_json(assistant["private_output"]):
            return False
        calls = assistant["tool_calls"]
        if type(calls) is not list or len(calls) > __WORLD_FORGE_MAX_TOOL_CALLS_PER_TURN__:
            return False
        index += 1
        for call in calls:
            if type(call) is not dict or set(call) != {
                "neutral_call_id", "tool_id", "private_arguments"
            }:
                return False
            call_id = call["neutral_call_id"]
            if (
                not exact_neutral_call_id(call_id)
                or call_id in seen
                or not exact_tool_id(call["tool_id"])
                or not exact_json(call["private_arguments"])
            ):
                return False
            seen.add(call_id)
            if index >= len(value):
                return False
            result = value[index]
            if type(result) is not dict or set(result) != {
                "role", "neutral_call_id", "tool_id", "private_output"
            }:
                return False
            if (
                result["role"] != "tool_result"
                or result["neutral_call_id"] != call_id
                or result["tool_id"] != call["tool_id"]
                or not exact_json(result["private_output"])
            ):
                return False
            index += 1
    return True

def exact_request(value):
    if type(value) is not dict or set(value) != {
        "execution_id", "turn_index", "private_input", "transcript",
        "tool_summaries", "exposed_tools"
    }:
        return False
    transcript = value["transcript"]
    summaries = value["tool_summaries"]
    definitions = value["exposed_tools"]
    if not exact_transcript(transcript):
        return False
    if type(summaries) is not list or len(summaries) > 128:
        return False
    summary_snapshots = {}
    for item in summaries:
        if type(item) is not dict or set(item) != {"tool_id", "summary", "descriptor_hash"}:
            return False
        tool_id = item["tool_id"]
        summary = item["summary"]
        if (
            not exact_tool_id(tool_id)
            or tool_id in summary_snapshots
            or type(summary) is not str
            or not summary
            or len(summary.encode("utf-8")) > 1024
            or any(ord(character) < 32 or ord(character) == 127 for character in summary)
            or not exact_sha256(item["descriptor_hash"])
        ):
            return False
        summary_snapshots[tool_id] = (item["descriptor_hash"], summary)
    if type(definitions) is not list or len(definitions) > 128:
        return False
    definition_ids = set()
    for item in definitions:
        if type(item) is not dict or set(item) != {
            "tool_id", "required_capability_id", "summary", "input_schema", "descriptor_hash"
        }:
            return False
        tool_id = item["tool_id"]
        body = {
            "tool_id": tool_id,
            "required_capability_id": item["required_capability_id"],
            "summary": item["summary"],
            "input_schema": item["input_schema"],
        }
        if (
            not exact_tool_id(tool_id)
            or tool_id in definition_ids
            or not exact_tool_id(item["required_capability_id"])
            or item["required_capability_id"] not in CAPABILITIES
            or type(item["summary"]) is not str
            or type(item["input_schema"]) is not dict
            or not exact_json(item["input_schema"], max_depth=32)
            or len(canonical(item["input_schema"])) > 16 * 1024
            or summary_snapshots.get(tool_id) != (item["descriptor_hash"], item["summary"])
            or digest(body) != item["descriptor_hash"]
        ):
            return False
        definition_ids.add(tool_id)
    return (
        exact_identifier(value["execution_id"])
        and type(value["turn_index"]) is int
        and 0 <= value["turn_index"] <= 64
        and exact_json(value["private_input"])
    )

def exact_runtime(value):
    return (
        type(value) is dict
        and set(value) == {"id", "revision", "content_hash"}
        and type(value["id"]) is str
        and value["id"] == RUNTIME["id"]
        and type(value["revision"]) is int
        and value["revision"] == RUNTIME["revision"]
        and exact_sha256(value["content_hash"])
        and value["content_hash"] == RUNTIME["content_hash"]
    )

def read_request(key):
    size = struct.unpack(">I", read_exact(4))[0]
    if size > MAX_REQUEST:
        raise ValueError()
    raw = read_exact(size)
    document = json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=pairs,
        parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
    )
    if canonical(document) != raw:
        raise ValueError()
    if set(document) != {
        "format", "format_version", "mac", "nonce", "request", "request_hash", "runtime"
    }:
        raise ValueError()
    if document["format"] != "world-forge.private.provider_turn_request":
        raise ValueError()
    if (
        type(document["format_version"]) is not int
        or document["format_version"] != 3
        or not exact_sha256(document["nonce"])
        or not exact_runtime(document["runtime"])
        or not exact_sha256(document["mac"])
        or not hmac.compare_digest(document["mac"], mac(document, key))
        or not exact_sha256(document["request_hash"])
        or not hmac.compare_digest(document["request_hash"], digest(document["request"]))
        or not exact_request(document["request"])
    ):
        raise ValueError()
    return document

def read_optional_frame(maximum):
    first = os.read(0, 4)
    if not first:
        return None
    while len(first) < 4:
        chunk = os.read(0, 4 - len(first))
        if not chunk:
            raise EOFError()
        first += chunk
    size = struct.unpack(">I", first)[0]
    if size > maximum:
        raise ValueError()
    return read_exact(size)

def decode_frame(raw):
    document = json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=pairs,
        parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
    )
    if type(document) is not dict or canonical(document) != raw:
        raise ValueError()
    return document

def exact_context(document, request_document, key):
    if type(document) is not dict or set(document) != {
        "format", "format_version", "gateway_policy_hash", "mac", "nonce",
        "original_request_hash", "runtime", "sequence"
    }:
        return False
    supplied = document["mac"]
    return (
        document["format"] == "world-forge.private.loopback_gateway_context"
        and type(document["format_version"]) is int
        and document["format_version"] == 1
        and type(document["sequence"]) is int
        and document["sequence"] == 0
        and exact_sha256(document["gateway_policy_hash"])
        and document["nonce"] == request_document["nonce"]
        and document["original_request_hash"] == request_document["request_hash"]
        and document["runtime"] == RUNTIME
        and exact_sha256(supplied)
        and hmac.compare_digest(supplied, mac(document, key))
    )

def gateway_document(format_name, context, body, key, response_challenge=None):
    body_bytes = canonical(body)
    maximum = (
        MAX_GATEWAY_REQUEST_BODY
        if format_name == "world-forge.private.loopback_gateway_request"
        else MAX_GATEWAY_RESPONSE_BODY
    )
    if len(body_bytes) > maximum:
        raise ValueError()
    document = {
        "body": body,
        "body_hash": hashlib.sha256(body_bytes).hexdigest(),
        "body_length": len(body_bytes),
        "format": format_name,
        "format_version": 1,
        "gateway_policy_hash": context["gateway_policy_hash"],
        "nonce": context["nonce"],
        "original_request_hash": context["original_request_hash"],
        "runtime": RUNTIME,
        "sequence": 0,
    }
    if format_name == "world-forge.private.loopback_gateway_response":
        if not exact_sha256(response_challenge):
            raise ValueError()
        document["response_challenge"] = response_challenge
        document["exchange_hash"] = digest(document)
    elif response_challenge is not None:
        raise ValueError()
    document["mac"] = mac(document, key)
    return document

def exact_gateway_response(document, context, key):
    if type(document) is not dict or set(document) != {
        "body", "body_hash", "body_length", "format", "format_version",
        "gateway_policy_hash", "mac", "nonce", "original_request_hash",
        "runtime", "sequence", "response_challenge", "exchange_hash"
    }:
        return False
    try:
        expected = gateway_document(
            "world-forge.private.loopback_gateway_response",
            context,
            document["body"],
            key,
            document["response_challenge"],
        )
    except BaseException:
        return False
    return document == expected

def write_frame(document, maximum):
    raw = canonical(document)
    if len(raw) > maximum:
        raise ValueError()
    write_all(1, struct.pack(">I", len(raw)) + raw)

def main():
    if len(sys.argv) != 1:
        raise ValueError()
    key = read_exact(32)
    request_document = read_request(key)
    request = request_document["request"]
    context_raw = read_optional_frame(MAX_GATEWAY_REQUEST)
    gateway_response = None
    gateway_response_hash = None
    gateway_exchange_hash = None
    if context_raw is not None:
        context = decode_frame(context_raw)
        if not exact_context(context, request_document, key):
            raise ValueError()
        gateway_body = {
            "execution_id": request["execution_id"],
            "transcript_hash": digest(request["transcript"]),
            "private_input_hash": digest(request["private_input"]),
            "turn_index": request["turn_index"],
        }
        write_frame(
            gateway_document(
                "world-forge.private.loopback_gateway_request",
                context,
                gateway_body,
                key,
            ),
            MAX_GATEWAY_REQUEST,
        )
        response_raw = read_optional_frame(MAX_GATEWAY_RESPONSE)
        if response_raw is None:
            raise EOFError()
        require_eof()
        response_document = decode_frame(response_raw)
        if not exact_gateway_response(response_document, context, key):
            raise ValueError()
        gateway_response = response_document["body"]
        gateway_response_hash = response_document["body_hash"]
        gateway_exchange_hash = response_document["exchange_hash"]
    private_output = {
        "execution_id": request["execution_id"],
        "exposed_tool_count": len(request["exposed_tools"]),
        "transcript_hash": digest(request["transcript"]),
        "private_input_hash": digest(request["private_input"]),
        "runtime_id": RUNTIME["id"],
        "tool_summary_count": len(request["tool_summaries"]),
        "turn_index": request["turn_index"],
    }
    if gateway_response is not None:
        private_output["gateway_response"] = gateway_response
        private_output["gateway_response_hash"] = gateway_response_hash
    result = {
        "private_output": private_output,
        "usage": {
            "input_tokens": {
                "state": "derived", "source_kind": "code_owned_runtime", "value": 1,
                "policy_hash": USAGE_POLICY_HASH, "unavailable_reason": None,
            },
            "output_tokens": {
                "state": "derived", "source_kind": "code_owned_runtime", "value": 1,
                "policy_hash": USAGE_POLICY_HASH, "unavailable_reason": None,
            },
            "cached_input_tokens": {
                "state": "unavailable", "source_kind": "none", "value": None,
                "policy_hash": None, "unavailable_reason": "code_owned_policy_absent",
            },
            "cost": {
                "state": "unavailable", "source_kind": "none", "value": None,
                "currency": None, "policy_hash": None,
                "unavailable_reason": "parent_pricing_unavailable",
            },
        },
        "tool_calls": [],
        "artifact_proposals": [],
        "memory_proposals": [],
        "tool_exposure_requests": [],
        "completed": True,
    }
    document = {
        "format": "world-forge.private.provider_turn_result",
        "format_version": 3,
        "nonce": request_document["nonce"],
        "request_hash": request_document["request_hash"],
        "result": result,
        "result_hash": digest(result),
        "runtime": RUNTIME,
    }
    if gateway_exchange_hash is not None:
        document["gateway_exchange_hash"] = gateway_exchange_hash
    document["mac"] = mac(document, key)
    raw = canonical(document)
    write_all(1, struct.pack(">I", len(raw)) + raw)

try:
    main()
except BaseException:
    os._exit(70)
"""

_DETERMINISTIC_PROBE_BOOTSTRAP_TEMPLATE = _embed_tool_call_limit(
    _DETERMINISTIC_PROBE_BOOTSTRAP_TEMPLATE_SOURCE
).replace(
    _USAGE_POLICY_HASH_TOKEN,
    code_owned_usage_policy_hash(_DETERMINISTIC_PROBE_RUNTIME_ID),
)


@dataclass(frozen=True, slots=True)
class _WorkerArtifact:
    identifier: str
    revision: int
    protocol_version: int
    bootstrap_template: str
    bootstrap_source: str
    content_hash: str


def _worker_artifact(
    *,
    identifier: str,
    revision: int,
    bootstrap_template: str,
) -> _WorkerArtifact:
    content_hash = hashlib.sha256(bootstrap_template.encode("utf-8")).hexdigest()
    return _WorkerArtifact(
        identifier=identifier,
        revision=revision,
        protocol_version=3,
        bootstrap_template=bootstrap_template,
        bootstrap_source=bootstrap_template.replace(
            RUNTIME_CONTENT_HASH_TOKEN,
            content_hash,
        ),
        content_hash=content_hash,
    )


def _conformance_worker_artifact() -> _WorkerArtifact:
    """Return a fresh immutable description of the pinned conformance worker."""

    return _worker_artifact(
        identifier=_CONFORMANCE_RUNTIME_ID,
        revision=_CONFORMANCE_RUNTIME_REVISION,
        bootstrap_template=WORKER_BOOTSTRAP_TEMPLATE,
    )


def _deterministic_probe_worker_artifact() -> _WorkerArtifact:
    """Return the fixed offline, non-production deterministic probe worker."""

    return _worker_artifact(
        identifier=_DETERMINISTIC_PROBE_RUNTIME_ID,
        revision=_DETERMINISTIC_PROBE_RUNTIME_REVISION,
        bootstrap_template=_DETERMINISTIC_PROBE_BOOTSTRAP_TEMPLATE,
    )


__all__ = (
    "RUNTIME_CONTENT_HASH_TOKEN",
    "WORKER_BOOTSTRAP",
    "WORKER_BOOTSTRAP_TEMPLATE",
)
