# Agent provider usage provenance TDD evidence

- Date: 2026-08-27
- Base revision: `a2eb9265`
- Scope: private Agent Harness provider-usage provenance and EventLog v3
- Mode: strict RED -> GREEN -> REFACTOR

## TDD Cycle Evidence

| Task | Test File | RED command and observed failure | GREEN command and result | Triangulation | Safety Net | Current GREEN mapping |
|---|---|---|---|---|---|---|
| U1 closed evidence/accounting module | `tests/test_agent_usage_provenance.py` | `PYTHONPATH=src python3 -m unittest tests.test_agent_usage_provenance -v` -> `ModuleNotFoundError: worldforge.agent_harness.usage` | Same command -> 6 tests, `OK` | Closed state/source/value/policy/reason coupling; safe integers; currency; mixed turns; cached bounds; legacy mode | Public receipt validation and kernel suites | `UsageEvidenceContractTests` in the current focused suite |
| U2 recognize but reject provider money | `tests/test_agent_usage_provenance.py` | Focused `test_money_requires_parent_pricing_and_joint_value_currency` -> `UsageEvidenceError: provider_usage_invalid` while constructing observed provider money | Full usage suite -> 6 tests, `OK` | Observed/provider-result and derived/parent-pricing-policy coupling; missing currency; wrong source/policy | Unpriced and provider-money kernel tests | Current focused usage suite |
| U3 exact legacy totals | `tests/test_agent_usage_provenance.py` | Focused legacy test with recomputed hash and boolean `input_tokens` -> `AssertionError: UsageEvidenceError not raised` | Full usage suite -> 6 tests, `OK` | Exact total shape, safe values, cached/input, joint cost/currency | EventLog receipt/accounting cross-check tests | Current focused usage suite |
| U3 exact discriminators | `tests/test_agent_usage_provenance.py` | Focused mixed-turn test with boolean `format_version` and `turn_index` -> two `AssertionError: UsageEvidenceError not raised` failures | Full usage suite -> 6 tests, `OK` | Both boolean aliases under recomputed canonical hashes | EventLog canonical decode and tamper tests | Current focused usage suite |
| C1 unavailable-input/cache coupling | `tests/test_agent_usage_provenance.py` | `PYTHONPATH=src python3 -m unittest tests.test_agent_usage_provenance.UsageEvidenceContractTests.test_input_cached_state_cross_product_is_provable_and_atomic -v` -> four failures for observed/derived cached `0`/`1` beside unavailable input | Same command -> 1 test, `OK` | Full observed/derived/unavailable input/cache cross-product, values `0`/`1`, correct/wrong policy hashes, prior-turn atomicity and cumulative public projection | Full usage and kernel suites | `test_input_cached_state_cross_product_is_provable_and_atomic` |
| C1 bounded kernel failure | `tests/test_agent_execution_kernel.py` | Before the evidence fix, unavailable input plus numeric cached evidence could reach receipt validation and raise `cached_input_tokens must not exceed input_tokens`; defensive seam test reproduced the uncaught `AgentHarnessContractError` | Focused unavailable-input and defensive-projection tests -> 2 tests, `OK` | Observed/derived cached `0`/`1`; invalid coupling returns `provider_usage_invalid` with zero mutation; valid prior accounting is restored if ledger projection is corrupted | Complete execution-kernel suite and EventLog atomic finalization | `test_unavailable_input_rejects_every_numeric_cached_claim_atomically`; `test_impossible_internal_projection_terminalizes_as_bounded_provider_failure` |
| D1 EventLog v3 compatibility | `tests/test_agent_event_log.py`, `tests/test_agent_memory_projection.py` | Initial integration run exposed every stale direct call as `TypeError: AgentEventLog.finalize() missing ... usage_accounting` | EventLog 47 tests and memory projection 40 tests, `OK` | v1/v2 migration/recovery, v3 missing/deleted/tampered accounting, WAL/hot-journal and atomic fault seams | Public contract pins and runtime suites | Included in current bounded Harness/EventLog gate |

The U1 module-level RED prevented individual cases from importing; it is not
represented as per-test execution. D1 is recorded as compatibility regression
closure, not retroactively claimed as a test-first production cycle.

## Current bounded GREEN gates

```text
PYTHONPATH=src python3 -m unittest \
  tests.test_agent_usage_provenance \
  tests.test_agent_execution_kernel
Ran 73 tests in 1.269s
OK
```

The final affected Harness/EventLog and native Linux commands are rerun after
the C1 remediation. Their exact current counts and durations replace the older
pre-review values before handoff.

```text
PYTHONPATH=src python3 -m unittest \
  tests.test_agent_harness_contracts \
  tests.test_agent_usage_provenance \
  tests.test_agent_execution_kernel \
  tests.test_agent_event_log \
  tests.test_agent_memory_projection \
  tests.test_agent_correlated_transcript
Ran 200 tests in 10.023s
OK

# Real Linux host
PYTHONPATH=src python3 -m unittest \
  tests.test_agent_worker_supervisor \
  tests.test_agent_runtime_dispatch \
  tests.test_agent_loopback_gateway \
  tests.test_agent_provider_governance
Ran 129 tests in 15.891s
OK

# Real Linux host
PYTHONPATH=src python3 -m unittest \
  tests.test_agent_human_approval tests.test_agent_worker_egress
Ran 41 tests in 1.455s
OK
```

## Identity audit evidence

Root ran the canonical identity allowlist generator once with authorization;
the generated allowlist change is retained. Current source-root audit:

```text
PYTHONPATH=src python3 -m worldforge audit-identities --source-root .
OK entries=299 occurrences=1040 \
allowlist=contracts/legacy-identity-allowlist.json
```

No sandbox generator run is part of this remediation.

## Refactor

Ruff import ordering, exact-type simplification, line wrapping, and formatting
run only after the focused C1 tests are green. Runtime identity pins and public
Agent Harness fixture bytes remain separate safety gates.
