"""Pinned, non-blocking input reads for codebase-memory benchmark evidence."""

from __future__ import annotations

import json
import math
import os
import stat
import sys
from pathlib import Path
from typing import Any

from worldforge.asset_io import (
    AssetContractError,
    PinnedOutputParent,
    _entry_info,
    open_verified_output_parent,
)
from worldforge.codebase_memory_benchmark import MAX_CODEBASE_MEMORY_BENCHMARK_DOCUMENT_BYTES
from worldforge.file_stat import FileStat, descriptor_file_stat, is_link_or_reparse


class CodebaseMemoryBenchmarkInputError(ValueError):
    """Raised when one explicit benchmark input cannot be read safely."""


def _benchmark_input_open_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )


def _validate_benchmark_input_state(info: FileStat, *, limit: int) -> tuple[int, int]:
    if is_link_or_reparse(info) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise CodebaseMemoryBenchmarkInputError("benchmark input must be a standalone regular file")
    if info.st_size > limit:
        raise CodebaseMemoryBenchmarkInputError(f"benchmark input exceeds the {limit}-byte limit")
    return info.st_dev, info.st_ino


def _state_signature(info: FileStat) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
        int(getattr(info, "st_file_attributes", 0)),
    )


def _read_benchmark_input_entry(
    parent: PinnedOutputParent,
    name: str,
    *,
    limit: int,
) -> bytes:
    descriptor: int | None = None
    windows_handle: int | None = None
    try:
        parent.assert_current()
        if parent.parent_fd is not None:
            descriptor = os.open(
                name,
                _benchmark_input_open_flags(),
                dir_fd=parent.parent_fd,
            )
            opened = descriptor_file_stat(descriptor)
        elif parent.windows_api is not None and parent.windows_parent_handle is not None:
            windows_handle = parent.windows_api.open_existing_file(
                parent.windows_parent_handle,
                name,
            )
            opened = parent.windows_api._state(
                windows_handle,
                directory=False,
                context=f"benchmark input {parent.path / name}",
            )
            descriptor = parent.windows_api.duplicate_to_descriptor(
                windows_handle,
                writable=False,
            )
        else:
            raise CodebaseMemoryBenchmarkInputError(
                "secure benchmark input primitives are unavailable"
            )

        opened_identity = _validate_benchmark_input_state(opened, limit=limit)
        named = _entry_info(parent, name)
        if named is None:
            raise CodebaseMemoryBenchmarkInputError("benchmark input name disappeared")
        if _validate_benchmark_input_state(named, limit=limit) != opened_identity:
            raise CodebaseMemoryBenchmarkInputError(
                "benchmark input name does not match the opened file"
            )

        payload = bytearray()
        while len(payload) <= limit:
            chunk = os.read(descriptor, min(64 * 1024, limit + 1 - len(payload)))
            if not chunk:
                break
            payload.extend(chunk)
        if len(payload) > limit:
            raise CodebaseMemoryBenchmarkInputError(
                f"benchmark input exceeds the {limit}-byte limit"
            )

        final = descriptor_file_stat(descriptor)
        named_after = _entry_info(parent, name)
        if named_after is None:
            raise CodebaseMemoryBenchmarkInputError("benchmark input name disappeared")
        if (
            _validate_benchmark_input_state(final, limit=limit) != opened_identity
            or _validate_benchmark_input_state(named_after, limit=limit) != opened_identity
            or _state_signature(final) != _state_signature(opened)
            or _state_signature(named_after) != _state_signature(named)
            or final.st_size != len(payload)
        ):
            raise CodebaseMemoryBenchmarkInputError("benchmark input changed while reading")
        parent.assert_current()
        return bytes(payload)
    finally:
        primary = sys.exception()
        cleanup_errors: list[Exception] = []
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError as exc:
                cleanup_errors.append(exc)
        if windows_handle is not None and parent.windows_api is not None:
            try:
                parent.windows_api.close(windows_handle)
            except (AssetContractError, OSError) as exc:
                cleanup_errors.append(exc)
        if cleanup_errors:
            if primary is not None:
                for exc in cleanup_errors:
                    primary.add_note(f"benchmark input cleanup failed: {exc}")
            else:
                first = cleanup_errors[0]
                for exc in cleanup_errors[1:]:
                    first.add_note(f"additional benchmark input cleanup failed: {exc}")
                raise first


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON object key: {key!r}")
        value[key] = item
    return value


def _reject_non_finite_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number: {value}")


def _parse_finite_json_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError(f"non-finite JSON number: {value}")
    return parsed


def read_codebase_memory_benchmark_json_object(
    path: str | Path,
) -> dict[str, Any]:
    """Read one explicit benchmark JSON file through retained ancestry handles."""

    requested = Path(path)
    destination = Path(os.path.abspath(requested))
    try:
        with open_verified_output_parent(destination.parent, create=False) as parent:
            payload = _read_benchmark_input_entry(
                parent,
                destination.name,
                limit=MAX_CODEBASE_MEMORY_BENCHMARK_DOCUMENT_BYTES,
            )
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_finite_json_constant,
            parse_float=_parse_finite_json_float,
        )
    except (
        AssetContractError,
        CodebaseMemoryBenchmarkInputError,
        OSError,
        MemoryError,
        OverflowError,
        RecursionError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
    ) as exc:
        raise CodebaseMemoryBenchmarkInputError(
            f"could not safely read benchmark input {requested}"
        ) from exc
    if not isinstance(value, dict):
        raise CodebaseMemoryBenchmarkInputError(
            f"benchmark input {requested} must contain a JSON object"
        )
    return value


__all__ = [
    "CodebaseMemoryBenchmarkInputError",
    "read_codebase_memory_benchmark_json_object",
]
