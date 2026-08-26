"""Code-owned bootstrap for the fixed private conformance worker."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

# This source is deliberately self-contained.  ``-I -S`` prevents the child
# from importing the checkout, so the supervisor passes no module or path.
_CONFORMANCE_RUNTIME_ID = "worldforge_conformance_provider"
_CONFORMANCE_RUNTIME_REVISION = 2
_RUNTIME_ID_TOKEN = "__WORLD_FORGE_RUNTIME_ID__"
_RUNTIME_REVISION_TOKEN = "__WORLD_FORGE_RUNTIME_REVISION__"
RUNTIME_CONTENT_HASH_TOKEN = "__WORLD_FORGE_RUNTIME_CONTENT_HASH__"
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
MAX_DEPTH = 64
MAX_HISTORY = 256
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

def exact_request(value):
    if type(value) is not dict or set(value) != {
        "execution_id", "turn_index", "private_input", "history",
        "tool_summaries", "exposed_tools"
    }:
        return False
    history = value["history"]
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
        and type(history) is list
        and len(history) <= MAX_HISTORY
        and all(exact_json(item) for item in history)
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
        or document["format_version"] != 1
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
        "format_version": 1,
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
        "input_tokens": 1,
        "output_tokens": 1,
        "cached_input_tokens": 0,
        "cost_minor_units": 0,
        "currency": "USD",
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

WORKER_BOOTSTRAP_TEMPLATE = _WORKER_BOOTSTRAP_TEMPLATE.replace(
    _RUNTIME_ID_TOKEN,
    _CONFORMANCE_RUNTIME_ID,
).replace(
    _RUNTIME_REVISION_TOKEN,
    str(_CONFORMANCE_RUNTIME_REVISION),
)
_CONFORMANCE_RUNTIME_HASH = hashlib.sha256(WORKER_BOOTSTRAP_TEMPLATE.encode("utf-8")).hexdigest()
WORKER_BOOTSTRAP = WORKER_BOOTSTRAP_TEMPLATE.replace(
    RUNTIME_CONTENT_HASH_TOKEN,
    _CONFORMANCE_RUNTIME_HASH,
)


_DETERMINISTIC_PROBE_RUNTIME_ID = "worldforge_deterministic_probe_provider"
_DETERMINISTIC_PROBE_RUNTIME_REVISION = 1
_DETERMINISTIC_PROBE_BOOTSTRAP_TEMPLATE = r"""
import hashlib
import hmac
import json
import math
import os
import struct
import sys

MAX_REQUEST = 256 * 1024
RUNTIME = {
    "id": "worldforge_deterministic_probe_provider",
    "revision": 1,
    "content_hash": "__WORLD_FORGE_RUNTIME_CONTENT_HASH__",
}
MAX_DEPTH = 64
MAX_HISTORY = 256
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

def exact_request(value):
    if type(value) is not dict or set(value) != {
        "execution_id", "turn_index", "private_input", "history",
        "tool_summaries", "exposed_tools"
    }:
        return False
    history = value["history"]
    summaries = value["tool_summaries"]
    definitions = value["exposed_tools"]
    if type(history) is not list or len(history) > MAX_HISTORY:
        return False
    if not all(exact_json(item) for item in history):
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
    require_eof()
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
        or document["format_version"] != 1
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

def main():
    if len(sys.argv) != 1:
        raise ValueError()
    key = read_exact(32)
    request_document = read_request(key)
    request = request_document["request"]
    result = {
        "private_output": {
            "execution_id": request["execution_id"],
            "exposed_tool_count": len(request["exposed_tools"]),
            "history_hash": digest(request["history"]),
            "private_input_hash": digest(request["private_input"]),
            "runtime_id": RUNTIME["id"],
            "tool_summary_count": len(request["tool_summaries"]),
            "turn_index": request["turn_index"],
        },
        "usage": {
            "input_tokens": 1,
            "output_tokens": 1,
            "cached_input_tokens": 0,
            "cost_minor_units": 0,
            "currency": "USD",
        },
        "tool_calls": [],
        "artifact_proposals": [],
        "memory_proposals": [],
        "tool_exposure_requests": [],
        "completed": True,
    }
    document = {
        "format": "world-forge.private.provider_turn_result",
        "format_version": 1,
        "nonce": request_document["nonce"],
        "request_hash": request_document["request_hash"],
        "result": result,
        "result_hash": digest(result),
        "runtime": RUNTIME,
    }
    document["mac"] = mac(document, key)
    raw = canonical(document)
    write_all(1, struct.pack(">I", len(raw)) + raw)

try:
    main()
except BaseException:
    os._exit(70)
"""


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
        protocol_version=1,
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
