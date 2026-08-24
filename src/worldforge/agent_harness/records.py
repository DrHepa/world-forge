"""Deterministic builders for the existing public Agent Harness records."""

from __future__ import annotations

import copy
from typing import Any

from worldforge.agent_harness_contracts import (
    AGENT_EVENT_FORMAT,
    AGENT_EXECUTION_RECEIPT_FORMAT,
    AGENT_HARNESS_VERSION,
    canonical_agent_harness_hash,
    validate_agent_harness_document,
)


def _seal(document: dict[str, Any]) -> dict[str, Any]:
    document["content_hash"] = canonical_agent_harness_hash(document)
    return validate_agent_harness_document(document)


def build_event(
    *,
    event_id: str,
    log_id: str,
    execution_id: str,
    sequence: int,
    previous_event_hash: str | None,
    event_type: str,
    subject_format: str,
    subject_id: str,
    subject_hash: str,
) -> dict[str, Any]:
    return _seal(
        {
            "format": AGENT_EVENT_FORMAT,
            "format_version": AGENT_HARNESS_VERSION,
            "event_id": event_id,
            "log_id": log_id,
            "execution_id": execution_id,
            "sequence": sequence,
            "previous_event_hash": previous_event_hash,
            "event_type": event_type,
            "subject": {
                "format": subject_format,
                "format_version": AGENT_HARNESS_VERSION,
                "id": subject_id,
                "content_hash": subject_hash,
            },
            "content_hash": "",
        }
    )


def build_receipt(
    *,
    receipt_id: str,
    activation: dict[str, Any],
    grant: dict[str, Any],
    tool_invocations: list[dict[str, Any]],
    result_artifacts: list[dict[str, str]],
    usage: dict[str, object],
    outcome: str,
    failure_codes: list[str],
) -> dict[str, Any]:
    return _seal(
        {
            "format": AGENT_EXECUTION_RECEIPT_FORMAT,
            "format_version": AGENT_HARNESS_VERSION,
            "receipt_id": receipt_id,
            "execution_id": activation["execution_id"],
            "activation": {
                "id": activation["activation_id"],
                "content_hash": activation["content_hash"],
            },
            "grant": {"id": grant["grant_id"], "content_hash": grant["content_hash"]},
            "runtime_binding": copy.deepcopy(activation["runtime"]),
            "prompt_identities": [copy.deepcopy(activation["prompt"])],
            "tool_invocations": copy.deepcopy(tool_invocations),
            "result_artifacts": copy.deepcopy(result_artifacts),
            "usage": copy.deepcopy(usage),
            "outcome": outcome,
            "failure_codes": sorted(set(failure_codes)),
            "replay_support": "not_claimed",
            "content_hash": "",
        }
    )
