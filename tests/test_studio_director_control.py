from __future__ import annotations

import gc
import io
import json
import tempfile
import unittest
import weakref
from pathlib import Path
from unittest import mock

from worldforge.agent_harness.approvals import ExecutionApprovalReview
from worldforge.studio.contracts import validate_studio_protocol_envelope
from worldforge.studio.director_control import StudioDirectorControl
from worldforge.studio.errors import StudioError
from worldforge.studio.service import StudioService, serve
from worldforge.studio.storage import StudioStore


PASSPHRASE = "correct horse battery staple"


def _review(*, suffix: str = "01") -> ExecutionApprovalReview:
    return ExecutionApprovalReview.create(
        approval_id=f"approval_execution_{suffix}",
        execution_id=f"execution_{suffix}",
        activation_hash="a" * 64,
        grant_hash="b" * 64,
        private_input_hash="c" * 64,
        runtime_id="worldforge_conformance_provider",
        runtime_revision=1,
        runtime_content_hash="d" * 64,
        max_turns=4,
        max_tool_calls=8,
        max_total_tokens=100,
        max_cost_minor_units=25,
        currency="USD",
        max_duration_ms=5_000,
        deadline_ms=10_000,
        tool_candidates=(("source.read", "e" * 64), ("world.validate", "f" * 64)),
    )


def _request(method: str, params: dict[str, object], request_id: str) -> dict[str, object]:
    return {
        "protocol": "rpg-world-forge.studio_protocol",
        "protocol_version": 6,
        "kind": "request",
        "request_id": request_id,
        "method": method,
        "params": params,
    }


class StudioDirectorControlTests(unittest.TestCase):
    def test_credential_lifecycle_is_explicit_and_every_new_control_starts_locked(self) -> None:
        with tempfile.TemporaryDirectory() as directory, StudioStore(
            Path(directory) / "data"
        ) as store:
            control = StudioDirectorControl(store)
            self.assertEqual(
                {"credential_id": "director_local", "state": "not_enrolled"},
                control.status(),
            )

            self.assertEqual("unlocked", control.enroll(passphrase=PASSPHRASE)["state"])
            authority_reference = weakref.ref(control._authority)
            self.assertEqual("locked", control.lock()["state"])
            gc.collect()
            self.assertIsNone(authority_reference())

            restarted = StudioDirectorControl(store)
            self.assertEqual("locked", restarted.status()["state"])
            with self.assertRaisesRegex(StudioError, "authentication failed") as wrong:
                restarted.unlock(passphrase="this passphrase is definitely wrong")
            self.assertEqual("invalid_state", wrong.exception.code)
            self.assertEqual("unlocked", restarted.unlock(passphrase=PASSPHRASE)["state"])

            with self.assertRaisesRegex(StudioError, "already unlocked") as duplicate:
                restarted.unlock(passphrase=PASSPHRASE)
            self.assertEqual("invalid_state", duplicate.exception.code)

            restarted.close()
            self.assertIsNone(restarted._authority)
            with self.assertRaisesRegex(StudioError, "Director control is closed"):
                restarted.status()

    def test_lock_remains_non_authoritative_when_credential_status_temporarily_fails(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory, StudioStore(
            Path(directory) / "data"
        ) as store:
            control = StudioDirectorControl(store)
            control.enroll(passphrase=PASSPHRASE)
            review = _review(suffix="lock_failure")

            with mock.patch.object(
                control,
                "_credential_enrolled",
                side_effect=StudioError(
                    "internal_error", "Director credential status failed"
                ),
            ):
                self.assertEqual(
                    {"credential_id": "director_local", "state": "locked"},
                    control.lock(),
                )
                self.assertIsNone(control._authority)
                with self.assertRaisesRegex(StudioError, "credential is locked"):
                    control.inspect(review.as_document())
                with self.assertRaisesRegex(StudioError, "credential status failed"):
                    control.status()

            self.assertEqual(
                {"credential_id": "director_local", "state": "locked"},
                control.status(),
            )

    def test_credential_mutations_do_not_query_status_after_installing_authority(
        self,
    ) -> None:
        for mode in ("enroll", "unlock"):
            with (
                self.subTest(mode=mode),
                tempfile.TemporaryDirectory() as directory,
                StudioStore(Path(directory) / "data") as store,
            ):
                control = StudioDirectorControl(store)
                if mode == "unlock":
                    control.enroll(passphrase=PASSPHRASE)
                    control.lock()

                with mock.patch.object(
                    control,
                    "_credential_enrolled",
                    side_effect=StudioError(
                        "internal_error", "Director credential status failed"
                    ),
                ):
                    status = getattr(control, mode)(passphrase=PASSPHRASE)

                self.assertEqual(
                    {"credential_id": "director_local", "state": "unlocked"},
                    status,
                )
                self.assertIsNotNone(control._authority)

    def test_exact_review_can_be_inspected_prepared_approved_and_revoked(self) -> None:
        with tempfile.TemporaryDirectory() as directory, StudioStore(
            Path(directory) / "data"
        ) as store:
            control = StudioDirectorControl(store)
            review = _review()
            document = review.as_document()

            with self.assertRaisesRegex(StudioError, "credential is locked") as locked:
                control.inspect(document)
            self.assertEqual("invalid_state", locked.exception.code)

            control.enroll(passphrase=PASSPHRASE)
            missing = control.inspect(document)
            self.assertEqual("missing", missing["state"])
            self.assertEqual(review.content_hash, missing["review_hash"])

            prepared = control.prepare(document, expected_generation=0)
            self.assertEqual("prepared", prepared["state"])
            self.assertEqual(document, prepared["prepared_review"])

            approved = control.approve(
                document,
                expected_generation=0,
                expected_review_hash=review.content_hash,
                approved_tool_ids=["source.read"],
                expires_at_ms=9_000,
            )
            self.assertEqual("approved", approved["state"])
            self.assertEqual("director_local", approved["current_decision"]["reviewer_id"])
            self.assertEqual(["source.read"], approved["current_decision"]["approved_tool_ids"])

            revoked = control.revoke(
                document,
                expected_generation=1,
                expected_decision_hash=approved["decision_hash"],
            )
            self.assertEqual("revoked", revoked["state"])
            self.assertEqual(2, revoked["generation"])

    def test_deny_and_error_translation_do_not_create_renderer_authority(self) -> None:
        with tempfile.TemporaryDirectory() as directory, StudioStore(
            Path(directory) / "data"
        ) as store:
            control = StudioDirectorControl(store)
            control.enroll(passphrase=PASSPHRASE)
            review = _review(suffix="02")
            document = review.as_document()
            control.prepare(document, expected_generation=0)

            denied = control.deny(
                document,
                expected_generation=0,
                expected_review_hash=review.content_hash,
            )
            decision = denied["current_decision"]
            self.assertEqual("denied", denied["state"])
            self.assertEqual("director_local", decision["reviewer_id"])
            self.assertEqual([], decision["approved_tool_ids"])
            self.assertIsNone(decision["expires_at_ms"])

            with self.assertRaisesRegex(StudioError, "review state changed") as stale:
                control.revoke(
                    document,
                    expected_generation=1,
                    expected_decision_hash="0" * 64,
                )
            self.assertEqual("conflict", stale.exception.code)

            malformed = {**document, "content_hash": "0" * 64}
            with self.assertRaisesRegex(StudioError, "review data is invalid") as invalid:
                control.inspect(malformed)
            self.assertEqual("invalid_request", invalid.exception.code)

    def test_protocol_v6_dispatches_only_through_service_owned_control(self) -> None:
        with tempfile.TemporaryDirectory() as directory, StudioStore(
            Path(directory) / "data"
        ) as store:
            service = StudioService(store)
            initialized = service.handle(_request("service.initialize", {}, "init-6"))
            self.assertEqual(6, initialized["result"]["service_version"])
            self.assertEqual(
                {
                    "authenticated_director_decisions": True,
                    "harness_hydration": False,
                    "civil_identity": False,
                    "secure_zeroization": False,
                },
                initialized["result"]["capabilities"],
            )

            status = service.handle(_request("director.status", {}, "status-6"))
            self.assertEqual("not_enrolled", status["result"]["status"]["state"])
            enrolled = service.handle(
                _request("director.enroll", {"passphrase": PASSPHRASE}, "enroll-6")
            )
            self.assertEqual("unlocked", enrolled["result"]["status"]["state"])

            review = _review(suffix="03")
            prepared = service.handle(
                _request(
                    "director.review.prepare",
                    {"review": review.as_document(), "expected_generation": 0},
                    "prepare-6",
                )
            )
            self.assertEqual("prepared", prepared["result"]["snapshot"]["state"])

            service.close()
            self.assertIsNone(service.director._authority)

    def test_protocol_v6_invalid_request_id_returns_a_valid_uncorrelated_error(self) -> None:
        request = _request("director.status", {}, "Request With Spaces")
        payload = (json.dumps(request, separators=(",", ":")) + "\n").encode("utf-8")
        output = io.BytesIO()
        with tempfile.TemporaryDirectory() as directory:
            exit_code = serve(
                io.BytesIO(payload),
                output,
                data_dir=Path(directory) / "data",
            )

        self.assertEqual(0, exit_code)
        response = json.loads(output.getvalue())
        self.assertEqual(6, response["protocol_version"])
        self.assertEqual("error", response["kind"])
        self.assertIsNone(response["request_id"])
        validate_studio_protocol_envelope(response)

    def test_protocol_v6_surrogate_passphrases_return_correlated_invalid_request(
        self,
    ) -> None:
        for request_id, passphrase in (
            ("surrogate_high", "\ud800" * 6),
            ("surrogate_low", "\udfff" * 6),
            ("surrogate_terminal_high", "a" * 16 + "\ud800"),
        ):
            request = _request("director.enroll", {"passphrase": passphrase}, request_id)
            payload = (json.dumps(request, separators=(",", ":")) + "\n").encode(
                "utf-8"
            )
            output = io.BytesIO()
            with self.subTest(request_id=request_id), tempfile.TemporaryDirectory() as directory:
                exit_code = serve(
                    io.BytesIO(payload),
                    output,
                    data_dir=Path(directory) / "data",
                )

                self.assertEqual(0, exit_code)
                response = json.loads(output.getvalue())
                self.assertEqual("error", response["kind"])
                self.assertEqual(request_id, response["request_id"])
                self.assertEqual("invalid_request", response["error"]["code"])
                validate_studio_protocol_envelope(response)

    def test_protocol_v6_credential_rejections_keep_correlated_domain_codes(
        self,
    ) -> None:
        wrong = "this passphrase is definitely wrong"
        review = _review(suffix="codes")
        review_document = review.as_document()
        requests = (
            _request("director.enroll", {"passphrase": PASSPHRASE}, "enroll_codes"),
            _request("director.lock", {}, "lock_codes"),
            _request("director.unlock", {"passphrase": "too short"}, "invalid_codes"),
            _request("director.unlock", {"passphrase": wrong}, "wrong_codes"),
            _request("director.unlock", {"passphrase": PASSPHRASE}, "recover_codes"),
            _request(
                "director.review.prepare",
                {"review": review_document, "expected_generation": 0},
                "prepare_codes",
            ),
            _request(
                "director.review.deny",
                {
                    "review": review_document,
                    "expected_generation": 0,
                    "expected_review_hash": review.content_hash,
                },
                "deny_codes",
            ),
            _request(
                "director.review.revoke",
                {
                    "review": review_document,
                    "expected_generation": 1,
                    "expected_decision_hash": "0" * 64,
                },
                "conflict_codes",
            ),
        )
        payload = b"".join(
            (json.dumps(request, separators=(",", ":")) + "\n").encode("utf-8")
            for request in requests
        )
        output = io.BytesIO()
        with tempfile.TemporaryDirectory() as directory:
            exit_code = serve(
                io.BytesIO(payload),
                output,
                data_dir=Path(directory) / "data",
            )

        self.assertEqual(0, exit_code)
        responses = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual(8, len(responses))
        self.assertEqual("invalid_request", responses[2]["error"]["code"])
        self.assertEqual("invalid_codes", responses[2]["request_id"])
        self.assertEqual("invalid_state", responses[3]["error"]["code"])
        self.assertEqual("wrong_codes", responses[3]["request_id"])
        self.assertEqual("unlocked", responses[4]["result"]["status"]["state"])
        self.assertEqual("prepared", responses[5]["result"]["snapshot"]["state"])
        self.assertEqual("denied", responses[6]["result"]["snapshot"]["state"])
        self.assertEqual("conflict", responses[7]["error"]["code"])
        self.assertEqual("conflict_codes", responses[7]["request_id"])
        rendered = output.getvalue().decode("utf-8")
        self.assertNotIn("too short", rendered)
        self.assertNotIn(wrong, rendered)
        for response in responses:
            validate_studio_protocol_envelope(response)


if __name__ == "__main__":
    unittest.main()
