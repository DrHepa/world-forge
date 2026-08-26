from __future__ import annotations

import hashlib
import json
import unittest

from worldforge.agent_harness.usage import (
    CostEvidence,
    TokenEvidence,
    UsageAccounting,
    UsageEvidenceError,
    build_legacy_usage_accounting,
    canonical_usage_hash,
    validate_usage_accounting,
)
from worldforge.agent_harness_contracts import MAX_SAFE_INTEGER

POLICY_A = hashlib.sha256(b"usage-policy-a").hexdigest()
POLICY_B = hashlib.sha256(b"usage-policy-b").hexdigest()
PRICING = hashlib.sha256(b"pricing-policy").hexdigest()


class UsageEvidenceContractTests(unittest.TestCase):
    @staticmethod
    def _token(state: str, value: int | None, *, policy: str = POLICY_A) -> TokenEvidence:
        if state == "observed":
            return TokenEvidence.create(
                state=state,
                source_kind="provider_result",
                value=value,
            )
        if state == "derived":
            return TokenEvidence.create(
                state=state,
                source_kind="code_owned_runtime",
                value=value,
                policy_hash=policy,
            )
        return TokenEvidence.create(
            state="unavailable",
            source_kind="none",
            unavailable_reason="provider_omitted",
        )

    def test_observed_derived_and_unavailable_token_coupling_is_closed(self) -> None:
        observed = TokenEvidence.create(state="observed", source_kind="provider_result", value=7)
        derived = TokenEvidence.create(
            state="derived",
            source_kind="code_owned_runtime",
            value=5,
            policy_hash=POLICY_A,
        )
        unavailable = TokenEvidence.create(
            state="unavailable",
            source_kind="none",
            unavailable_reason="provider_omitted",
        )
        self.assertEqual(("observed", 7), (observed.state, observed.value))
        self.assertEqual(("derived", POLICY_A), (derived.state, derived.policy_hash))
        self.assertEqual(
            (None, "provider_omitted"),
            (unavailable.value, unavailable.unavailable_reason),
        )

        invalid = (
            {
                "state": "unavailable",
                "source_kind": "none",
                "value": 0,
                "unavailable_reason": "provider_omitted",
            },
            {"state": "observed", "source_kind": "provider_result", "value": None},
            {"state": "derived", "source_kind": "code_owned_runtime", "value": 1},
            {"state": "observed", "source_kind": "code_owned_runtime", "value": 1},
            {"state": "mystery", "source_kind": "none", "value": None},
            {
                "state": "unavailable",
                "source_kind": "none",
                "value": None,
                "unavailable_reason": "hostile",
            },
        )
        for values in invalid:
            with self.subTest(values=values), self.assertRaises(UsageEvidenceError):
                TokenEvidence.create(**values)

    def test_exact_numeric_hash_and_currency_types_reject_aliases_and_overflow(self) -> None:
        class IntAlias(int):
            pass

        class TextAlias(str):
            pass

        for value in (True, -1, MAX_SAFE_INTEGER + 1, IntAlias(1)):
            with self.subTest(value=value), self.assertRaises(UsageEvidenceError):
                TokenEvidence.create(state="observed", source_kind="provider_result", value=value)
        for currency in ("usd", "USDX", TextAlias("USD")):
            with self.subTest(currency=currency), self.assertRaises(UsageEvidenceError):
                CostEvidence.create(
                    state="derived",
                    source_kind="parent_pricing_policy",
                    value=1,
                    currency=currency,
                    policy_hash=PRICING,
                )

    def test_money_requires_parent_pricing_and_joint_value_currency(self) -> None:
        provider_claim = CostEvidence.create(
            state="observed",
            source_kind="provider_result",
            value=9,
            currency="USD",
        )
        self.assertEqual((9, "USD"), (provider_claim.value, provider_claim.currency))
        priced = CostEvidence.create(
            state="derived",
            source_kind="parent_pricing_policy",
            value=11,
            currency="USD",
            policy_hash=PRICING,
        )
        self.assertEqual((11, "USD"), (priced.value, priced.currency))
        unavailable = CostEvidence.create(
            state="unavailable",
            source_kind="none",
            unavailable_reason="parent_pricing_unavailable",
        )
        self.assertEqual((None, None), (unavailable.value, unavailable.currency))
        for values in (
            {
                "state": "derived",
                "source_kind": "code_owned_runtime",
                "value": 1,
                "currency": "USD",
                "policy_hash": POLICY_A,
            },
            {
                "state": "derived",
                "source_kind": "parent_pricing_policy",
                "value": 1,
                "currency": None,
                "policy_hash": PRICING,
            },
            {
                "state": "unavailable",
                "source_kind": "none",
                "value": None,
                "currency": "USD",
                "unavailable_reason": "parent_pricing_unavailable",
            },
        ):
            with self.subTest(values=values), self.assertRaises(UsageEvidenceError):
                CostEvidence.create(**values)

        accounting = UsageAccounting.create(
            execution_id="execution_usage_money",
            runtime_spec_hash=POLICY_B,
            selection_hash=hashlib.sha256(b"selection-money").hexdigest(),
            usage_policy_hash=POLICY_A,
            pricing_policy_hash=None,
        )
        with self.assertRaises(UsageEvidenceError):
            accounting.add_turn(
                input_tokens=TokenEvidence.create(
                    state="observed", source_kind="provider_result", value=1
                ),
                output_tokens=TokenEvidence.create(
                    state="observed", source_kind="provider_result", value=1
                ),
                cached_input_tokens=TokenEvidence.create(
                    state="unavailable",
                    source_kind="none",
                    unavailable_reason="provider_omitted",
                ),
                cost=provider_claim,
            )

    def test_accounting_projects_mixed_turns_and_seals_unavailable_before_failure(self) -> None:
        accounting = UsageAccounting.create(
            execution_id="execution_usage_01",
            runtime_spec_hash=POLICY_B,
            selection_hash=hashlib.sha256(b"selection").hexdigest(),
            usage_policy_hash=POLICY_A,
            pricing_policy_hash=None,
        )
        accounting.add_turn(
            input_tokens=TokenEvidence.create(
                state="observed", source_kind="provider_result", value=7
            ),
            output_tokens=TokenEvidence.create(
                state="derived",
                source_kind="code_owned_runtime",
                value=5,
                policy_hash=POLICY_A,
            ),
            cached_input_tokens=TokenEvidence.create(
                state="unavailable",
                source_kind="none",
                unavailable_reason="provider_omitted",
            ),
            cost=CostEvidence.create(
                state="unavailable",
                source_kind="none",
                unavailable_reason="parent_pricing_unavailable",
            ),
        )
        accounting.add_turn(
            input_tokens=TokenEvidence.create(
                state="derived",
                source_kind="code_owned_runtime",
                value=3,
                policy_hash=POLICY_A,
            ),
            output_tokens=TokenEvidence.create(
                state="observed", source_kind="provider_result", value=2
            ),
            cached_input_tokens=TokenEvidence.create(
                state="observed", source_kind="provider_result", value=2
            ),
            cost=CostEvidence.create(
                state="unavailable",
                source_kind="none",
                unavailable_reason="parent_pricing_unavailable",
            ),
        )
        document = accounting.seal(receipt_hash=POLICY_B)
        self.assertEqual(
            {
                "input_tokens": 10,
                "output_tokens": 7,
                "cached_input_tokens": 2,
                "cost_minor_units": None,
                "currency": None,
            },
            document["recognized_totals"],
        )
        self.assertEqual(2, document["turn_count"])
        self.assertEqual(canonical_usage_hash(document), document["content_hash"])
        for mutation in ("format_version", "turn_index"):
            hostile = json.loads(json.dumps(document))
            if mutation == "format_version":
                hostile["format_version"] = True
            else:
                hostile["turns"][0]["turn_index"] = False
            hostile["content_hash"] = canonical_usage_hash(hostile)
            with self.subTest(mutation=mutation), self.assertRaises(UsageEvidenceError):
                validate_usage_accounting(hostile)

    def test_cached_value_cannot_exceed_same_turn_input_and_overflow_is_closed(self) -> None:
        accounting = UsageAccounting.create(
            execution_id="execution_usage_02",
            runtime_spec_hash=POLICY_B,
            selection_hash=hashlib.sha256(b"selection-2").hexdigest(),
            usage_policy_hash=POLICY_A,
            pricing_policy_hash=None,
        )
        cases = ((3, 4), (MAX_SAFE_INTEGER, 1))
        for input_value, cached_value in cases:
            with (
                self.subTest(values=(input_value, cached_value)),
                self.assertRaises(UsageEvidenceError),
            ):
                accounting.add_turn(
                    input_tokens=TokenEvidence.create(
                        state="observed", source_kind="provider_result", value=input_value
                    ),
                    output_tokens=TokenEvidence.create(
                        state="observed",
                        source_kind="provider_result",
                        value=1 if input_value == MAX_SAFE_INTEGER else 0,
                    ),
                    cached_input_tokens=TokenEvidence.create(
                        state="observed", source_kind="provider_result", value=cached_value
                    ),
                    cost=CostEvidence.create(
                        state="unavailable",
                        source_kind="none",
                        unavailable_reason="parent_pricing_unavailable",
                    ),
                )

    def test_input_cached_state_cross_product_is_provable_and_atomic(self) -> None:
        cost = CostEvidence.create(
            state="unavailable",
            source_kind="none",
            unavailable_reason="parent_pricing_unavailable",
        )
        input_cases = (
            ("observed", 0),
            ("observed", 1),
            ("derived", 0),
            ("derived", 1),
            ("unavailable", None),
        )
        cached_cases = (
            ("observed", 0),
            ("observed", 1),
            ("derived", 0),
            ("derived", 1),
            ("unavailable", None),
        )
        for input_case in input_cases:
            for cached_case in cached_cases:
                with self.subTest(input=input_case, cached=cached_case):
                    accounting = UsageAccounting.create(
                        execution_id="execution_usage_cross_product",
                        runtime_spec_hash=POLICY_B,
                        selection_hash=hashlib.sha256(b"selection-cross").hexdigest(),
                        usage_policy_hash=POLICY_A,
                        pricing_policy_hash=None,
                    )
                    accounting.add_turn(
                        input_tokens=self._token("observed", 2),
                        output_tokens=self._token("observed", 1),
                        cached_input_tokens=self._token("observed", 1),
                        cost=cost,
                    )
                    before = (accounting.turn_count, dict(accounting.recognized_totals))
                    input_evidence = self._token(*input_case)
                    cached_evidence = self._token(*cached_case)
                    accepted = (
                        cached_case[0] == "unavailable"
                        or input_case[0] != "unavailable"
                        and cached_case[1] <= input_case[1]
                    )
                    if accepted:
                        accounting.add_turn(
                            input_tokens=input_evidence,
                            output_tokens=self._token("observed", 0),
                            cached_input_tokens=cached_evidence,
                            cost=cost,
                        )
                        totals = accounting.recognized_totals
                        self.assertLessEqual(totals["cached_input_tokens"], totals["input_tokens"])
                    else:
                        with self.assertRaises(UsageEvidenceError):
                            accounting.add_turn(
                                input_tokens=input_evidence,
                                output_tokens=self._token("observed", 0),
                                cached_input_tokens=cached_evidence,
                                cost=cost,
                            )
                        self.assertEqual(
                            before,
                            (accounting.turn_count, accounting.recognized_totals),
                        )

        for field, policy in (("input", POLICY_B), ("cached", POLICY_B)):
            with self.subTest(wrong_policy=field):
                accounting = UsageAccounting.create(
                    execution_id="execution_usage_policy_cross",
                    runtime_spec_hash=POLICY_B,
                    selection_hash=hashlib.sha256(b"selection-policy-cross").hexdigest(),
                    usage_policy_hash=POLICY_A,
                    pricing_policy_hash=None,
                )
                before = (accounting.turn_count, dict(accounting.recognized_totals))
                with self.assertRaises(UsageEvidenceError):
                    accounting.add_turn(
                        input_tokens=self._token(
                            "derived", 1, policy=policy if field == "input" else POLICY_A
                        ),
                        output_tokens=self._token("observed", 0),
                        cached_input_tokens=self._token(
                            "derived", 0, policy=policy if field == "cached" else POLICY_A
                        ),
                        cost=cost,
                    )
                self.assertEqual(before, (accounting.turn_count, accounting.recognized_totals))

    def test_legacy_accounting_keeps_receipt_totals_without_claiming_observation(self) -> None:
        receipt = {
            "execution_id": "execution_legacy_01",
            "content_hash": POLICY_B,
            "usage": {
                "input_tokens": 3,
                "output_tokens": 2,
                "cached_input_tokens": 1,
                "duration_ms": 4,
                "cost_minor_units": 0,
                "currency": "USD",
            },
        }
        document = build_legacy_usage_accounting(receipt)
        self.assertEqual("legacy_receipt_totals", document["record_mode"])
        self.assertEqual([], document["turns"])
        self.assertEqual(receipt["usage"] | {}, document["recognized_totals"] | {"duration_ms": 4})
        self.assertNotIn("observed", json.dumps(document))

        hostile = json.loads(json.dumps(document))
        hostile["recognized_totals"]["input_tokens"] = True
        hostile["content_hash"] = canonical_usage_hash(hostile)
        with self.assertRaises(UsageEvidenceError):
            validate_usage_accounting(hostile)


if __name__ == "__main__":
    unittest.main()
