# Agent parent exact pricing TDD evidence

- Date: 2026-08-27
- Base revision: `f60b3a9`
- Scope: private parent-owned exact synthetic pricing authority
- Mode: strict RED -> GREEN -> TRIANGULATE -> REFACTOR

## TDD Cycle Evidence

| Task | Test File | RED command and observed failure | GREEN command and result | Triangulation | Safety Net |
|---|---|---|---|---|---|
| P1 closed pricing module | `tests/test_agent_parent_pricing.py` | `PYTHONPATH=src python3 -m unittest tests.test_agent_parent_pricing -v` -> `ModuleNotFoundError: worldforge.agent_harness.pricing` | Same command -> 9 tests, `OK`; final triangulated suite -> 10 tests, `OK` | Exact policy/rates, scalar aliases, overflow, equal/unequal cache rates, mutation and closed resolution | 120 usage/kernel/EventLog tests plus 37 pure governance/runtime/protocol tests, `OK` |
| P2 live parent accounting | `tests/test_agent_parent_pricing.py` | No isolated live-accounting RED transcript was retained. The initial missing-module RED proves test-first ordering only; it is not claimed as behavior-specific proof. | Focused pricing suite -> `OK` | Derived and observed forged worker money, parent replacement, default `2 XTS`, no ceiling, exact/+1 token/cost limits | Existing usage and kernel budget suites |
| P3 exact overflow failure | `tests/test_agent_parent_pricing.py` | Focused exact-scalar test -> expected `provider_usage_invalid`, observed `provider_pricing_overflow` | Same focused test -> 1 test, `OK` | Pure overflow and kernel atomic bounded failure with zero recorded usage | Existing safe-integer and impossible-projection tests |
| P4 duplicate zero live pricing | `tests/test_agent_parent_pricing.py` | Focused duplicate test -> expected one live calculator call, observed eight because durable validation reused the live entry point | Same focused test -> 1 test, `OK` | Separate deterministic recorded-arithmetic verifier; duplicate performs zero additional provider/live-pricing calls | Existing exact-terminal duplicate and EventLog replay tests |
| P5 durable verification and compatibility | `tests/test_agent_parent_pricing.py` | The captured duplicate/replay RED observed eight live-calculator calls, proving durable reread incorrectly entered the live path. No separate raw transcript for the first EventLog tamper RED was retained, so none is claimed. | Focused pricing suite -> `OK` | Rehashed accounting tamper, legacy no-reprice, runtime/protocol pins, policy/catalog/selection drift | EventLog v3 and public contract suites |
| P6 construction-time pricing authority | `tests/test_agent_runtime_dispatch.py` | Native affected gate -> `provider_usage_policy_invalid` when the regression test removed the mutable runtime registry after kernel construction | Focused native dispatch test -> 1 test, `OK`; native affected gate -> 167 tests, `OK` | Sole policy is installed once from the immutable registry snapshot; later registry/factory mutation cannot retarget or remove it | Existing frozen-dispatch mutation test |
| P7 authoritative priced lineage | `tests/test_agent_parent_pricing.py` | Three focused tests -> 5 assertion failures: catalog rebinding was accepted, opaque priced accounting construction succeeded, and replay accepted individual/joint rehashed lineage. Follow-up focused REDs each failed once because a caller-forged resolution and a partial jointly rehashed lineage/accounting pair were still accepted while the execution request row remained unchanged. | Initial focused set -> 3 tests, `OK`; both follow-up tests -> `OK`; final pre-remediation pricing suite -> 15 tests, `OK` | Canonical XTS rebind, opaque/forged resolution construction, semantic request/lineage linkage, finalize/replay individual and partial joint runtime/selection drift | Existing EventLog, catalog, usage, and kernel suites |
| P8 exact two-runtime pricing shape | `tests/test_agent_parent_pricing.py` | `PYTHONPATH=src python3 -m unittest` with the three new focused methods -> 5 assertion failures and 1 error: stripped/replaced probe pricing and arbitrary conformance pricing entered catalogs, direct stripped/replaced probe lineage construction succeeded, and the kernel path reached only its later generic catalog rejection. | Same three focused methods (the direct-lineage method was then renamed while triangulating conformance) -> 3 tests, `OK` | Probe requires the canonical triple/usage/policy/`XTS`; conformance is exactly unpriced; direct lineage and caller-catalog kernel input fail at the pricing authority boundary | 105 non-native pricing/catalog/governance/kernel tests, `OK`; the combined managed-sandbox native class retained its pre-existing missing-worker-PID environment failure |
| P9 owner-bound catalog resolution and exact conformance | `tests/test_agent_parent_pricing.py` | Five focused methods -> 9 failures: three forged conformance identity mutations entered catalogs, durable accounting and real EventLog replay accepted forged conformance, two arbitrary live probe lineage hashes were accepted, and two copied issued-lineage hash mutations reached durable begin. After the first GREEN, three additional focused methods -> 3 failures because a caller catalog, a copied resolved selection, and a value-only copy of the code-owned catalog still retained or acquired live authority. | Initial five focused methods -> 5 tests, `OK`; second three focused methods -> 3 tests, `OK`; final pricing suite -> 26 tests, `OK` | Exact unpriced conformance triple/usage binding; owner-bound code-owned catalog, resolution, and live-lineage capabilities; copied/caller-issued authority rejection; durable semantic reconstruction remains separate from live issuance | 313 non-native affected tests, 167 real-host native tests, and 17 isolated egress tests, `OK` |
| P10 registered object authority and journal compatibility | `tests/test_agent_parent_pricing.py` | Six focused methods -> 14 failures and 1 error: `object.__new__`, replacement and subclass catalogs borrowed embedded proofs; the generic issuer authorized caller specifications; copied or coherently mutated resolutions and live lineages retargeted selected hashes; conformance failed against the prior journal signature; and `ports.py` differed from `f60b3a9`. Follow-up private-extension test -> 1 failure because it also accepted an unpriced lineage. | Four authority methods -> 4 tests, `OK`; journal/port methods -> 2 tests, `OK`; private-extension follow-up -> 1 test, `OK`; combined six after refactor -> 6 tests, `OK`; final pricing suite -> 33 tests, `OK` | Exact strong identity-plus-hash registries with no embedded proof; closed no-catalog-argument root factory; copy/subclass/clone/borrow/owner-swap/mutation/hash rejection; baseline unpriced journal call; priced-only private extension and early legacy rejection | Round-4 pre-edit safety net 168 tests, final affected 320, real-host native 167, and isolated egress 17, `OK` |
| P11 bounded authority lifetime and intended recorded-cost validation | `tests/test_agent_parent_pricing.py` | Four focused methods -> 2 failures and 2 errors: 1,000 discarded cycles grew catalog/resolution/lineage registries from `(1, 0, 0)` to `(2001, 2000, 1000)`; the classes could not be weak-referenced; no stale-callback retirement seam existed; and the wrong-cost fixture reached the recorded verifier twice instead of exactly once. | Three registry methods -> 3 tests, `OK`; recorded-cost method -> 1 test, `OK`; final pricing suite -> 36 tests, `OK` | Weak-reference collection, bounded registry counts, retained live authority, exact-ref stale callback defense, all prior copy/clone/owner-swap attacks, and a resealed first-turn wrong cost through trusted durable lineage reaching `_verify_recorded_execution_cost` exactly once | Round-5 pre-edit pricing safety net -> 33 tests, `OK`; final affected 323, real-host native 167, and isolated egress 17, `OK` |

The request/lineage commitment evidence is intentionally limited to semantic
consistency against the accepted execution row. It is unkeyed and is not an
independent/authenticated anchor. Per ADR-0032, no test claims resistance to a
same-UID adversary that coherently replaces all affected projections and hashes.
The durable selection hash binds the accepted selection document, but the exact
selection fields cannot be reconstructed from that hash alone.

Round-2 RED (the direct-lineage method had its pre-triangulation name):

```text
PYTHONPATH=src python3 -m unittest \
  tests.test_agent_parent_pricing.ExactParentPricingTests.test_catalog_requires_exact_pricing_shape_for_both_code_owned_runtimes \
  tests.test_agent_parent_pricing.ExactParentPricingTests.test_direct_lineage_rejects_stripped_or_replaced_probe_pricing \
  tests.test_agent_parent_pricing.ExactParentPricingTests.test_kernel_input_cannot_carry_a_stripped_probe_catalog -v
Ran 3 tests
FAILED (failures=5, errors=1)
```

Round-2 GREEN after the direct-lineage conformance triangulation:

```text
PYTHONPATH=src python3 -m unittest \
  tests.test_agent_parent_pricing.ExactParentPricingTests.test_catalog_requires_exact_pricing_shape_for_both_code_owned_runtimes \
  tests.test_agent_parent_pricing.ExactParentPricingTests.test_direct_lineage_requires_closed_two_runtime_pricing_shape \
  tests.test_agent_parent_pricing.ExactParentPricingTests.test_kernel_input_cannot_carry_a_stripped_probe_catalog -v
Ran 3 tests
OK
```

Round-3 initial RED and GREEN (the accounting method was renamed while
triangulating durable reconstruction):

```text
PYTHONPATH=src python3 -m unittest \
  tests.test_agent_parent_pricing.ExactParentPricingTests.test_catalog_requires_exact_code_owned_conformance_identity \
  tests.test_agent_parent_pricing.ExactParentPricingTests.test_accounting_rejects_resolved_forged_conformance_identity \
  tests.test_agent_parent_pricing.ExactParentPricingTests.test_event_log_replay_rejects_forged_conformance_identity \
  tests.test_agent_parent_pricing.ExactParentPricingTests.test_direct_live_probe_lineage_rejects_arbitrary_selected_hashes \
  tests.test_agent_parent_pricing.ExactParentPricingTests.test_event_log_begin_rejects_copied_issued_lineage_hash_drift -v
Ran 5 tests
FAILED (failures=9)

# The accounting case was narrowed to durable stored reconstruction before GREEN.
PYTHONPATH=src python3 -m unittest \
  tests.test_agent_parent_pricing.ExactParentPricingTests.test_catalog_requires_exact_code_owned_conformance_identity \
  tests.test_agent_parent_pricing.ExactParentPricingTests.test_accounting_rejects_durable_forged_conformance_identity \
  tests.test_agent_parent_pricing.ExactParentPricingTests.test_event_log_replay_rejects_forged_conformance_identity \
  tests.test_agent_parent_pricing.ExactParentPricingTests.test_direct_live_probe_lineage_rejects_arbitrary_selected_hashes \
  tests.test_agent_parent_pricing.ExactParentPricingTests.test_event_log_begin_rejects_copied_issued_lineage_hash_drift -v
Ran 5 tests in 0.117s
OK
```

Round-3 authority triangulation RED and GREEN:

```text
PYTHONPATH=src python3 -m unittest \
  tests.test_agent_parent_pricing.ExactParentPricingTests.test_priced_accounting_requires_code_owned_catalog_resolution \
  tests.test_agent_parent_pricing.ExactParentPricingTests.test_priced_accounting_rejects_copied_resolved_selection \
  tests.test_agent_parent_pricing.ExactParentPricingTests.test_kernel_rejects_value_only_copy_of_code_owned_catalog -v
Ran 3 tests
FAILED (failures=3)

# Same command after owner-bound catalog/resolution issuance
Ran 3 tests in 0.011s
OK
```

Round-4 transferable-authority and public-journal RED:

```text
PYTHONPATH=src python3 -m unittest \
  tests.test_agent_parent_pricing.ExactParentPricingTests.test_catalog_authority_rejects_object_new_replace_and_borrowed_owner \
  tests.test_agent_parent_pricing.ExactParentPricingTests.test_generic_catalog_issuer_cannot_authorize_caller_specs \
  tests.test_agent_parent_pricing.ExactParentPricingTests.test_resolved_authority_rejects_copies_subclasses_and_coherent_mutation \
  tests.test_agent_parent_pricing.ExactParentPricingTests.test_live_lineage_authority_rejects_proof_theft_and_retargeted_hashes \
  tests.test_agent_parent_pricing.ExactParentPricingTests.test_legacy_journal_signature_remains_compatible_and_pricing_fails_early \
  tests.test_agent_parent_pricing.ExactParentPricingTests.test_execution_journal_public_port_bytes_match_baseline -v
Ran 6 tests
FAILED (failures=14, errors=1)
```

Round-4 GREEN and refactor:

```text
# Identity-authority subset after replacing embedded proofs
Ran 4 tests in 0.046s
OK

# Legacy journal and protected-port subset after private extension routing
Ran 2 tests in 0.018s
OK

# Combined six after formatting/refactor
Ran 6 tests in 0.065s
OK

# Priced-only private-extension triangulation
PYTHONPATH=src python3 -m unittest \
  tests.test_agent_parent_pricing.ExactParentPricingTests.test_private_priced_journal_extension_rejects_unpriced_lineage -v
Ran 1 test in 0.037s
FAILED (failures=1)

# Same command after the extension rejected unpriced lineage
Ran 1 test in 0.033s
OK
```

During the journal GREEN cycle, the first test harness used a bare kernel and
therefore exercised the existing missing-governance failure instead of the
legacy journal. It was changed to the established auto-governed conformance
helper; its expectations were then corrected to the canonical `succeeded`
outcome and normal appended-event sequence. No production exception or omitted
lineage path was introduced.

Round-5 authority-lifetime and recorded-cost RED:

```text
PYTHONPATH=src python3 -m unittest \
  tests.test_agent_parent_pricing.ExactParentPricingTests.test_authority_registries_release_completed_objects_after_gc \
  tests.test_agent_parent_pricing.ExactParentPricingTests.test_authority_registries_keep_live_objects_and_release_collected_objects \
  tests.test_agent_parent_pricing.ExactParentPricingTests.test_authority_registry_stale_callback_cannot_retire_new_registration \
  tests.test_agent_parent_pricing.ExactParentPricingTests.test_execution_total_rounding_is_split_invariant_and_recomputed -v
Ran 4 tests in 1.347s
FAILED (failures=2, errors=2)
```

The stress failure measured registry growth from `(1, 0, 0)` to
`(2001, 2000, 1000)` after collection. The other registry failures were the
missing weak-reference support and deterministic stale-callback seam. The
recorded-cost mock reached `_verify_recorded_execution_cost` twice because the
initial hostile document changed its second turn. The final fixture changes the
first recorded turn, so the valid durable-lineage path recomputes exactly once
and rejects that resealed cost mismatch for `provider_usage_invalid`.

Round-5 GREEN and triangulation:

```text
# Weak lifetime, retained-live-authority, collection, and stale callback subset
Ran 3 tests in 1.335s
OK

# Trusted durable-lineage recorded-cost validation
Ran 1 test in 0.010s
OK

# Prior object-new/copy/subclass/owner-swap/coherent-mutation attacks
Ran 4 tests in 0.048s
OK

# Final focused suite after formatting/refactor
Ran 36 tests in 2.248s
OK
```

## Safety-net evidence

Before production edits:

```text
PYTHONPATH=src python3 -m unittest \
  tests.test_agent_usage_provenance \
  tests.test_agent_execution_kernel \
  tests.test_agent_event_log -q
Ran 120 tests in 5.445s
OK

PYTHONPATH=src python3 -m unittest \
  tests.test_agent_provider_governance.ProviderRuntimeCatalogTests \
  tests.test_agent_provider_governance.ProviderGovernanceAuthorityTests \
  tests.test_agent_provider_governance.ProviderGovernanceKernelTests \
  tests.test_agent_runtime_dispatch.ConformanceRuntimeApprovalTests \
  tests.test_agent_runtime_dispatch.CodeOwnedRuntimeRegistryTests \
  tests.test_agent_runtime_dispatch.RuntimeBoundProtocolTests \
  tests.test_agent_worker_supervisor.WorkerRequestDecoderHardeningTests -q
Ran 37 tests in 0.844s
OK

# Round-4 focused safety net before its production edits
PYTHONPATH=src python3 -m unittest \
  tests.test_agent_parent_pricing \
  tests.test_agent_execution_kernel \
  tests.test_agent_event_log \
  tests.test_agent_harness_contracts -q
Ran 168 tests in 7.190s
OK

# Round-5 focused safety net before its production edits
PYTHONPATH=src python3 -m unittest tests.test_agent_parent_pricing -q
Ran 33 tests in 1.052s
OK
```

The combined native supervisor baseline was also attempted in the managed
sandbox. It produced pre-existing `Operation not permitted` socket/seccomp
failures and `ProviderBoundaryIndeterminate`; these are environment failures,
not accepted GREEN evidence. Native verification must run outside that sandbox.

The first Round-3 affected-suite run then reported 1 failure and 7 errors in
generic provider-governance tests. Their shared fixture reused the now-reserved
`worldforge_conformance_provider` ID with arbitrary revision, content, and usage
hashes. The fixture was renamed to the neutral `test_conformance_provider`; no
production exception was added. Its 10 focused catalog/authority tests and the
complete 313-test affected rerun passed.

## Final bounded GREEN gates

```text
PYTHONPATH=src python3 -m unittest tests.test_agent_parent_pricing -q
Ran 36 tests in 2.248s
OK

PYTHONPATH=src python3 -m unittest \
  tests.test_agent_parent_pricing \
  tests.test_agent_harness_contracts \
  tests.test_agent_usage_provenance \
  tests.test_agent_execution_kernel \
  tests.test_agent_event_log \
  tests.test_agent_memory_projection \
  tests.test_agent_correlated_transcript \
  tests.test_agent_human_approval.HumanApprovalAuthorityTests \
  tests.test_agent_human_approval.ToolDescriptorSnapshotTests \
  tests.test_agent_human_approval.KernelApprovalAndProgressiveExposureTests \
  tests.test_agent_human_approval.ProgressiveExposureProtocolTests \
  tests.test_agent_provider_governance.ProviderRuntimeCatalogTests \
  tests.test_agent_provider_governance.ProviderGovernanceAuthorityTests \
  tests.test_agent_provider_governance.ProviderGovernanceKernelTests \
  tests.test_agent_runtime_dispatch.ConformanceRuntimeApprovalTests \
  tests.test_agent_runtime_dispatch.CodeOwnedRuntimeRegistryTests \
  tests.test_agent_runtime_dispatch.RuntimeBoundProtocolTests \
  tests.test_agent_worker_supervisor.WorkerRequestDecoderHardeningTests \
  tests.test_architecture -q
Ran 323 tests in 13.715s
OK

# Post-documentation architecture regression
PYTHONPATH=src python3 -m unittest tests.test_architecture -q
Ran 29 tests in 0.167s
OK

# Real Linux host; worker/supervisor/dispatch/loopback/governance/approval
PYTHONPATH=src python3 -m unittest \
  tests.test_agent_worker_supervisor \
  tests.test_agent_runtime_dispatch \
  tests.test_agent_loopback_gateway \
  tests.test_agent_provider_governance \
  tests.test_agent_human_approval -q
Ran 167 tests in 18.161s
OK

# Real Linux host; isolated because its preexec seccomp checks cannot safely
# follow the prior multi-threaded suite in the same interpreter.
PYTHONPATH=src python3 -m unittest tests.test_agent_worker_egress -q
Ran 17 tests in 0.148s
OK

<project-venv>/bin/ruff check <affected files>
All checks passed!

<project-venv>/bin/ruff format --check <affected files>
13 files already formatted

PYTHONPATH=src python3 -m worldforge audit-runtime src/isoworld
OK runtime=src/isoworld ai_imports=0

PYTHONPATH=src python3 -m worldforge audit-contracts --source-root .
OK contracts=130 mode=source catalog=<repo>/contracts/catalog.json

protected public manifest before/after diff
PROTECTED_PUBLIC_BYTES_IDENTICAL
```

The canonical identity generator was not invoked during this remediation, and
no allowlist byte was hand-edited. Root must run the canonical generator after
review, then rerun `worldforge audit-identities`; the current expected stale row
is `README.md` (allowlist hash
`08d5414b8761de99a5979342215098adcf2908ecb03aedfae38c03b155bf2277`,
observed hash
`325b6fbe44baacf3644cb66a70d9910a72bd25e05e74ec7ca63ecf03605d48e3`).
Process inspection found no surviving provider, worker, or Harness child.

## Refactor

The live pricing transition and recorded-arithmetic verifier now share one pure
checked integer core without sharing the live entry point. Ruff organizes and
formats the bounded affected files after all focused behavior remains green.
Construction authority now stores only identity-checked weak references plus
immutable hash snapshots; exact-reference callback retirement avoids both
unbounded object retention and stale-ID deletion.
