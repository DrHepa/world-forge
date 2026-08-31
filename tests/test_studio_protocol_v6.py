from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path

from worldforge.studio.contracts import (
    METHODS_V6,
    STUDIO_PROTOCOL_V6,
    validate_studio_protocol_envelope,
)
from worldforge.studio.errors import StudioContractError


ROOT = Path(__file__).resolve().parents[1]
HASH = "a" * 64
PUBLIC_PROTOCOL_HASHES = {
    "schemas/studio-protocol.schema.json": (
        "8b3ac19494aca6b2cb37906dbfdab2ab7ea85bb5c21937c96fe9622a74c2c060"
    ),
    "schemas/studio-protocol-v2.schema.json": (
        "cfb96c6c17d49136cb1938c6ada5f70e155b2dd179f6690ab2701cb070762ce9"
    ),
    "schemas/studio-protocol-v3.schema.json": (
        "367abd7a9cb4bede12ff9d968b88b601073c7eaa27d8ac9a307e4c1361d42e2d"
    ),
    "schemas/studio-protocol-v4.schema.json": (
        "28d3a8fa4c65cc902a9661044bebf6625916672d7252bb8bb32e48ff875d4ea5"
    ),
    "schemas/studio-protocol-v5.schema.json": (
        "8012ae63195c6159df46f7bcfad74ff2afe43d6d9c59fc60aa5949948f29f751"
    ),
    "apps/studio/src/generated/studio-protocol.d.ts": (
        "79974583002cb407d16b53bcf90cfded0560753eb290c0d0c134fbb0f288ae07"
    ),
    "apps/studio/src/generated/studio-protocol-v2.d.ts": (
        "370b4804a790e56b7ac63402a4244667e7b009dfd08dbbd9a1b75e7f0178fead"
    ),
    "apps/studio/src/generated/studio-protocol-v3.d.ts": (
        "3726bc1b218f9faef3230091a252a9d706b26e3187dec518fedac7370db8dabf"
    ),
    "apps/studio/src/generated/studio-protocol-v4.d.ts": (
        "1901911ecab5952faa750ebfa402f11903b807c60b1d13cfc5369b4d5047053c"
    ),
    "apps/studio/src/generated/studio-protocol-v5.d.ts": (
        "f97e6294b4495fd27202b661d4f41907e7a19afbd160d90036bd39b660c92184"
    ),
}


def _review() -> dict[str, object]:
    return {
        "format": "world-forge.private.execution_approval_review",
        "format_version": 1,
        "approval_id": "approval_01",
        "execution_id": "execution_01",
        "activation_hash": HASH,
        "grant_hash": "b" * 64,
        "private_input_hash": "c" * 64,
        "runtime_id": "runtime_01",
        "runtime_revision": 1,
        "runtime_content_hash": "d" * 64,
        "max_turns": 4,
        "max_tool_calls": 2,
        "max_total_tokens": 4096,
        "max_cost_minor_units": 20,
        "currency": "XTS",
        "max_duration_ms": 30_000,
        "deadline_ms": 2_000_000_000_000,
        "tool_candidates": [
            {"tool_id": "forge.read", "descriptor_hash": "e" * 64},
            {"tool_id": "forge.write", "descriptor_hash": "f" * 64},
        ],
        "generation": 0,
        "content_hash": "0" * 64,
    }


def _request(method: str, params: dict[str, object]) -> dict[str, object]:
    return {
        "protocol": "rpg-world-forge.studio_protocol",
        "protocol_version": 6,
        "kind": "request",
        "request_id": "request_01",
        "method": method,
        "params": params,
    }


class StudioProtocolV6Tests(unittest.TestCase):
    def test_v6_is_an_independent_closed_director_capability_lane(self) -> None:
        self.assertEqual(6, STUDIO_PROTOCOL_V6)
        self.assertEqual(
            {
                "service.initialize",
                "director.status",
                "director.enroll",
                "director.unlock",
                "director.lock",
                "director.review.inspect",
                "director.review.prepare",
                "director.review.approve",
                "director.review.deny",
                "director.review.revoke",
            },
            set(METHODS_V6),
        )
        for method, params in (
            ("director.status", {}),
            ("director.enroll", {"passphrase": "correct horse battery staple"}),
            ("director.review.inspect", {"review": _review()}),
            (
                "director.review.approve",
                {
                    "review": _review(),
                    "expected_generation": 0,
                    "expected_review_hash": "0" * 64,
                    "approved_tool_ids": ["forge.read"],
                    "expires_at_ms": 2_000_000_030_000,
                },
            ),
        ):
            checked = validate_studio_protocol_envelope(_request(method, params))
            self.assertEqual(method, checked["method"])

    def test_v6_rejects_cross_lane_and_renderer_authority_fields(self) -> None:
        for value in (
            _request("creation_job.list", {}),
            _request("director.lock", {"approval_id": "approval_01"}),
            _request(
                "director.review.deny",
                {
                    "review": _review(),
                    "expected_generation": 0,
                    "expected_review_hash": "0" * 64,
                    "reviewer_id": "someone_else",
                },
            ),
            _request(
                "director.review.revoke",
                {
                    "review": _review(),
                    "expected_generation": 1,
                    "expected_decision_hash": "1" * 64,
                    "outcome": "revoked",
                },
            ),
        ):
            with self.subTest(value=value["method"]), self.assertRaises(StudioContractError):
                validate_studio_protocol_envelope(value)

    def test_v6_rejects_event_envelopes_and_invalid_request_ids(self) -> None:
        event = {
            "protocol": "rpg-world-forge.studio_protocol",
            "protocol_version": 6,
            "kind": "event",
            "request_id": None,
            "event": {},
        }
        with self.assertRaises(StudioContractError):
            validate_studio_protocol_envelope(event)

        for request_id in ("", "Request With Spaces"):
            invalid = _request("director.status", {})
            invalid["request_id"] = request_id
            with self.subTest(request_id=request_id), self.assertRaises(StudioContractError):
                validate_studio_protocol_envelope(invalid)

    def test_v6_passphrase_bounds_are_exact_utf8_bytes_in_both_validators(self) -> None:
        for method in ("director.enroll", "director.unlock"):
            for passphrase, accepted in (
                ("four", False),
                ("a" * 16, True),
                ("\ud800" * 6, False),
                ("\udfff" * 6, False),
                ("a" * 16 + "\ud800", False),
                ("😀" * 4, True),
                ("é" * 513, False),
                ("é" * 512, True),
            ):
                request = _request(method, {"passphrase": passphrase})
                with self.subTest(
                    method=method,
                    first_scalar=repr(passphrase[:1]),
                    characters=len(passphrase),
                ):
                    if accepted:
                        validate_studio_protocol_envelope(request)
                    else:
                        with self.assertRaises(StudioContractError):
                            validate_studio_protocol_envelope(request)

        schema = json.loads(
            (ROOT / "schemas/studio-protocol-v6.schema.json").read_text(encoding="utf-8")
        )
        passphrase_schema = schema["$defs"]["passphraseParams"]["properties"][
            "passphrase"
        ]
        self.assertEqual(
            {
                "type": "string",
                "x-worldforge-min-utf8-bytes": 16,
                "x-worldforge-max-utf8-bytes": 1024,
            },
            passphrase_schema,
        )
        declaration = (
            ROOT / "apps/studio/src/generated/studio-protocol-v6.d.ts"
        ).read_text(encoding="utf-8")
        self.assertIn("passphrase: string;", declaration)

    def test_v6_response_decisions_are_bounded_by_outcome_and_review_candidates(self) -> None:
        def decision(
            outcome: str,
            approved_tool_ids: list[str],
            expires_at_ms: int | None,
        ) -> dict[str, object]:
            return {
                "format": "world-forge.private.execution_approval_decision",
                "format_version": 1,
                "approval_id": "approval_01",
                "execution_id": "execution_01",
                "review_hash": "0" * 64,
                "generation": 1,
                "reviewer_id": "director_local",
                "outcome": outcome,
                "approved_tool_ids": approved_tool_ids,
                "expires_at_ms": expires_at_ms,
                "content_hash": "2" * 64,
            }

        def response(
            outcome: str,
            approved_tool_ids: list[str],
            expires_at_ms: int | None,
        ) -> dict[str, object]:
            review = _review()
            current_decision = decision(outcome, approved_tool_ids, expires_at_ms)
            return {
                "protocol": "rpg-world-forge.studio_protocol",
                "protocol_version": 6,
                "kind": "response",
                "request_id": "decision_response_01",
                "method": "director.review.approve",
                "result": {
                    "snapshot": {
                        "prepared_review": review,
                        "current_decision": current_decision,
                        "generation": 1,
                        "review_hash": review["content_hash"],
                        "decision_hash": current_decision["content_hash"],
                        "state": outcome,
                    }
                },
            }

        for valid in (
            response("denied", [], None),
            response("approved", ["forge.read"], 2_000_000_030_000),
        ):
            validate_studio_protocol_envelope(valid)
        for invalid in (
            response("denied", ["forge.read"], 2_000_000_030_000),
            response("denied", ["forge.read"], None),
            response("denied", [], 2_000_000_030_000),
            response("approved", ["outside.invoke"], 2_000_000_030_000),
            response(
                "approved",
                ["forge.write", "forge.read"],
                2_000_000_030_000,
            ),
        ):
            with self.subTest(invalid=invalid), self.assertRaises(StudioContractError):
                validate_studio_protocol_envelope(invalid)

    def test_v6_review_candidate_ids_are_unique_in_requests_and_responses(self) -> None:
        for conflicting_hash in (False, True):
            review = _review()
            candidates = review["tool_candidates"]
            self.assertIsInstance(candidates, list)
            duplicate = dict(candidates[0])
            if conflicting_hash:
                duplicate["descriptor_hash"] = "9" * 64
            candidates.append(duplicate)
            request = _request("director.review.inspect", {"review": review})
            response = {
                "protocol": "rpg-world-forge.studio_protocol",
                "protocol_version": 6,
                "kind": "response",
                "request_id": "duplicate_candidates_response_01",
                "method": "director.review.prepare",
                "result": {
                    "snapshot": {
                        "prepared_review": review,
                        "current_decision": None,
                        "generation": 0,
                        "review_hash": review["content_hash"],
                        "decision_hash": None,
                        "state": "prepared",
                    }
                },
            }
            for envelope in (request, response):
                with (
                    self.subTest(
                        conflicting_hash=conflicting_hash,
                        kind=envelope["kind"],
                    ),
                    self.assertRaises(StudioContractError),
                ):
                    validate_studio_protocol_envelope(envelope)

    def test_v6_schema_and_generated_declaration_are_additive(self) -> None:
        schema_path = ROOT / "schemas/studio-protocol-v6.schema.json"
        declaration_path = ROOT / "apps/studio/src/generated/studio-protocol-v6.d.ts"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        self.assertEqual(
            "https://world-forge.local/schemas/studio-protocol-v6.schema.json",
            schema["$id"],
        )
        declaration = declaration_path.read_text(encoding="utf-8")
        self.assertIn("WorldForgeStudioDirectorProtocolV6", declaration)
        self.assertIn('protocol_version: 6', declaration)
        for relative, expected in PUBLIC_PROTOCOL_HASHES.items():
            self.assertEqual(
                expected,
                hashlib.sha256((ROOT / relative).read_bytes()).hexdigest(),
                relative,
            )


if __name__ == "__main__":
    unittest.main()
