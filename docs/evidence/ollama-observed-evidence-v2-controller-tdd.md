# Ollama observed-evidence v2 controller core — strict TDD evidence

- Date: 2026-09-02
- Revision under test: working tree based on
  `211d52f4e8fd20f40e5cbceda7584b3ce8129bf9`
- Scope: ADR-0050-B private non-native controller core only
- Result: controller core functional; ADR-0050 remains **PARTIAL**
- Availability: `unavailable`
- Production eligibility: `false`
- Terminal apply state: `prepared_unverified`

## Safety boundary

The original Stage-B work added deterministic planning, exact private
contracts, a private durable controller store, closed effect dispatch, one-use
authorization, post-call observation, read-only reconciliation, and explicit
rollback. It did **not** add a concrete interpreter, subprocess or generic
command surface, POSIX account management, systemd integration, socket
lifecycle, Studio authority, provider adapter, model load, inference, or native
evidence. Stage C later added backend-only Studio schema-v8 settlement without
adding any of those absent native or provider boundaries.

All host-facing behavior was exercised through test-local fakes. No live
filesystem preparation, account/group change, service/process/socket/model
operation, network access, install, provider execution, or inference ran. The
SQLite tests used only temporary test databases. Fakes are not evidence of
native or systemd behavior.

## Safe baseline before edits

Only the existing pure ADR-0050-A contract suite ran before implementation:

```text
PYTHONPATH=src python3 -m unittest -v tests.test_ollama_observed_evidence_v2
Ran 14 tests
OK
```

No local-service/native selector and no full discovery ran.

## RED → GREEN → TRIANGULATE → REFACTOR

| Tranche | RED | GREEN | Triangulation and refactor |
|---|---|---|---|
| Exact contracts and planner | The focused suite first failed to import the absent controller-contract module. The first implementation then exposed a slotted-inheritance construction error. | Defining the zero-slot canonical base and the frozen/slotted exact contracts made canonical plan, snapshot, effect, authorization, operation, and rollback cases pass. | Added hostile extra/missing/wrong JSON types, bool-as-int, malformed path/hash/ID, NFC/casefold collision, dot/NUL, bounds, link/hardlink/writeability, overlap, ambient Ollama, numeric principal collision, policy/interpreter drift, forged rollback identity, and forged operation-state cases. Canonicalization and projection helpers were consolidated without loosening exact validation. |
| Private durable store | The focused suite first failed to import the absent store. Early runs exposed incomplete schema/replay and durable-linkage behavior. | The exact schema, `BEGIN IMMEDIATE` CAS transitions, canonical documents, event hash chain, authorization/attempt uniqueness, reopen verification, and exact duplicate suppression passed. | Fault injection covered every durable transition. A genuine hostile RED proved that operation-only commit fingerprints misclassified foreign related-row changes; the fingerprint was expanded to the complete operation/event/authorization/attempt state. Another RED added missing inflight authorization linkage verification. A style-only newline inside a unique-index DDL literal was detected by exact schema census and corrected without changing the schema bytes. |
| Controller state machine | The focused suite first failed to import the absent controller. | Closed inspector, authorization, and one-method-per-effect protocols passed apply, lost-reply resume, post-call observation, reconciliation, and explicit rollback cases. | Added denial, pre-call foreign drift, effect exception, observation failure, late instance/class replacement, duplicate resume, reverse proven-effect rollback, and preserved foreign-resource cases. An exhausted drift-preserving rollback initially made read-only reconciliation raise `rollback_effect_cursor_invalid`; a genuine RED now ends with an explicit `recovery_required` reconciliation result and no dispatch or authorization. |

### Round-1 adversarial review remediation

| Confirmed issue | Genuine RED | GREEN and triangulation |
|---|---|---|
| Complete host projection | After effect 1, removing the managed root still let the controller prepare and authorize effect 2. During rollback, a previously removed principal could reappear while later cleanup still progressed. | Every effect hash now covers the full stable host projection, including all ownership tokens. At the original Stage-B boundary, apply and rollback preflight ran before authorization and again before dispatch; post-call observation classified that same complete projection. Stage C later moved the first host preflight after terminal authorization settlement, while retaining complete pre-dispatch and post-call projection checks. |
| Same-operation duplicate dispatch | Two barrier-synchronized controllers sharing one store both consumed authorization and invoked the same effect after observing a duplicate historical transition. | Every mutation returns `ControllerStoreTransition(snapshot, committed_now)`. A durable pending-to-claimed transition assigns the sole caller allowed to consume, and only the dispatch-transition owner may invoke the effect. Barrier tests prove one consume, one effect call, and one cursor advance, including resume from an already-pending request. |
| Distinct-operation ownership | Two operation IDs could both become active for the fixed resources because no durable lease or resource capability distinguished ownership. | Plan/effect/authorization/operation/observation/rollback contracts bind an operation-specific ownership token. Operation creation transactionally acquires one fixed-host-scope lease, held through owned, prepared, and recovery states and released only at exact `rolled_back_clean`. Concurrent creation/apply and rollback barriers prove operation B neither credits nor deletes operation A resources. |
| Semantic reopen/replay | Reopen accepted an orphan pending authorization, altered consumed decision provenance, a postcondition attempt whose after-snapshot was rewritten to its pre-snapshot, missing completed rows, and an extra dispatch row without any transition event. Event documents also had no auxiliary bindings. | Closed event bindings now hash exact plans, requests, consumptions, effects, attempts, whole-host projections, ownership, recovery, and rollback. Reopen recomputes event identities and classifications, replays every operation snapshot mutation, and requires a one-to-one event/authorization/attempt census. Complete apply-plus-rollback replay and foreign-ownership projection tests triangulate the valid and hostile paths. |
| Independent numeric collisions | A UID-only collision could not be represented because the principal contract required UID-owner and GID-owner census values to appear together. | The censuses are independent; UID-only and GID-only collisions are both representable and both reject planning without adoption. |
| Assertion and class-replacement evidence | The hash test used the vacuous `content_hash.startswith("")`, and the class-replacement claim lacked a real post-construction class-method mutation. | The hash assertion requires exactly 64 lowercase hexadecimal characters and a meta-regression forbids the vacuous form. A runtime test replaces `OllamaV2Controller._dispatch` after construction, restores it in `finally`, and proves the captured original target still executes. |

### Round-2 adversarial review remediation

| Confirmed issue | Genuine RED | GREEN and triangulation |
|---|---|---|
| False clean manager marker | A complete nine-effect apply followed by complete rollback reached `rolled_back_clean` and released the host-scope lease while `manager_reload_ownership_token` still named operation A. | Rollback `manager.reload` now clears that ownership marker and increments the manager generation. Terminal state and both lease-deletion paths require a complete reusable-host projection, not cursor exhaustion. Full apply/rollback/reopen then permits a fresh inspected plan and operation B; a contract-level projection test independently proves the marker and generation semantics. |
| Active recovery latch | A zero-effect operation restored after temporary drift, and a nonzero applied prefix restored then exactly compensated, both remained `recovery_required` because historical `recovery_reason` was treated as an active permanent latch. | Exact reusable cleanup clears only the active reason; the historical recovery event remains immutable and replay-verifiable. Zero- and nonzero-effect regressions close/reopen the store and prove operation B can acquire the scope. A nonterminal rollback regression also proves ordinary compensation does not invent an active recovery reason. |

The reusable-clean predicate compares the whole initial and observed host
projection, permits only detached observation metadata and a monotonically
advanced manager generation, and requires both initial and terminal manager
ownership markers to be absent. The zero-effect rollback event binds the full
clean snapshot plus its content and projection hashes so semantic replay can
recompute the same terminal proof.

### Final publication-review remediation

| Confirmed issue | Genuine RED | GREEN and triangulation |
|---|---|---|
| Lease-released terminal reversal | Direct `record_recovery` from exact `rolled_back_clean` committed `recovery_required` without reacquiring the deleted lease. A separately constructed canonical recovery transition with a restored lease also survived reopen because semantic replay accepted recovery after any source state. | `rolled_back_clean` is now an immutable store terminal. Live recovery rejects it before event or row mutation, while semantic replay independently rejects a terminal-source recovery event. The regression proves the operation snapshot, generation, sequence, head, events, and absent lease remain exact, then proves a distinct operation claims the scope normally. Authorization and rollback-plan entrypoints are table-checked against the same terminal. |
| Recovery durable-boundary evidence | The generic commit reconciliation existed, but the evidence suite did not execute `record_recovery` before-commit and lost-post-commit paths explicitly. | Test-local `_commit` wrappers now prove an exception before commit leaves the exact operation/event/lease pre-state, and an exception after commit reconciles exactly one immediate post-state. Duplicate suppression, close/reopen semantic replay, orphan recovery events, and altered recovery event documents are all exercised without a production test hook. |

The “every durable transition” claim therefore includes explicit recovery
transition evidence rather than inference from the shared commit helper.

### Final concurrent-ownership remediation

| Confirmed issue | Genuine RED | GREEN and triangulation |
|---|---|---|
| Exception-reconciled post-state ownership | Caller A rolled back after a forced pre-commit exception and released the SQLite lock; caller B then committed the identical dispatch transition before A's probe. A observed B's exact post-state and incorrectly received `committed_now=True`. The synchronized regression failed exactly at `self.assertFalse(transition_results["a"].committed_now)` with `True is not false`; both callers could therefore enter the host-effect path. | `_finish_commit` now returns ownership only for a direct exception-free commit. Any exact post-state reconciled after an exception returns the durable snapshot with `committed_now=False`; exact pre-state still reports commit-not-applied, an exact duplicate remains non-owner, and a third state still poisons the operation. Both operation creation and the shared transition append path propagate that result. The synchronized test proves only caller B owns dispatch, with one authorization consumption, one effect call, and one cursor advance. |
| Lost post-commit reply coverage | Existing fault injection proved durable state equivalence but did not assert nonownership at every returned boundary or resume each controller phase. | Actual commit-then-lost-reply injections now cover creation, authorization pending/claimed/consumed, dispatching, effect observation, recovery, and rollback preparation. Every exception-reconciled post result is non-owner and reopens cleanly. Controller-level phase triangulation proves pending and consumed resume without duplicate consumption, dispatching resumes observation-only before a fresh authorized attempt, an observed result never repeats its effect, an uncertain claim enters explicit recovery, and recovery/rollback remain cleanly resumable. |

The first synchronized test fixture created SQLite connections in the main
thread and then used them in worker threads. Python's thread-affine SQLite
guard rejected that fixture before the intended race. Each worker now creates
and closes its own store connection; this was a test-fixture incident, not a
controller failure or host mutation. The corrected fixture then produced the
genuine ownership RED above.

Test fakes mutate only detached `HostSnapshot` values. Assertions prove concrete
production paths ran by checking persisted generations, sequences, event heads,
authorization identities, attempts, effect calls, projected host hashes,
rollback lineages, reopen behavior, and corruption failures.

## Delivered private contracts and APIs

`ollama_v2_controller_contracts.py` supplies frozen/slotted, exact
JSON-compatible contracts for:

- interpreter binding and bounded tree manifests;
- principal and unit observations plus the complete host snapshot;
- closed host effects and deterministic controller plans;
- authorization requests, consumptions, rejections, and the exact
  `AuthorizationOutcome` union;
- operation snapshots and rollback plans.

Every accepted document is rebuilt as a detached copy and has canonical JSON
bytes plus a canonical SHA-256 identity. The planner binds:

- policy content hash
  `c4fbf98a52896901bb46732935a7fbef462b7369105dab5bffcff381a3968f73`;
- policy serialized SHA-256
  `030f2a3432efc21d3f9915cd39575e334c47b24b58770935c5105e8f5d5c1322`;
- numeric UID/GID `9731:9731`;
- code-owned destinations, unit directory, exact unit bytes, interpreter
  contract bytes, and interpreter path;
- `native_implementation_state="absent"`.

The deterministic apply order is exactly:

1. `managed_root.create`
2. `principal.create_exact`
3. `release.stage`
4. `release.publish`
5. `model.stage`
6. `model.publish`
7. `socket.install`
8. `service.install`
9. `manager.reload`

Plans are bounded to at most 32 effects. Neither plans nor effects carry an
arbitrary command, argument vector, environment, unit body, shell fragment, or
generic RPC payload.

`OllamaV2ControllerStore` is independent of `StudioStore` and `EventLog`. Its
exact schema contains metadata, operations, events, authorizations, effect
attempts, one fixed-host-scope lease, and three explicit unique indices. It
verifies schema census, application/user versions, foreign keys, checks,
canonical stored documents, plan/rollback lineage, exact transition ownership,
authorization/attempt bijection, semantic event replay, complete host
classification, and the current generation/sequence/head/state CAS on creation
and reopen.

After an exception around commit, only the exact pre-transaction state or the
exact immediate post-transaction state is accepted. An exact post-state proves
the durable snapshot but returns `committed_now=False`, because it cannot prove
which concurrent caller committed that state. Any other state poisons the
operation and requires recovery. This detects torn or foreign adjacent state;
it does not claim protection against a coherent rollback performed by the same
OS principal.

`OllamaV2Controller` exposes only:

- `inspect`
- `build_plan`
- `create_operation`
- `status`
- `advance_apply`
- `reconcile`
- `prepare_rollback`
- `advance_rollback`

The inspector protocol has only `inspect` and `observe`; authorization has
only `consume` and `resolve`; effects have one named method for each of the 17
closed apply/rollback operations. All bound call targets are captured during
controller construction, so later instance or class replacement cannot
redirect an existing controller.

## Durable state model

The closed operation states are:

```text
apply_pending
apply_authorization_pending
apply_authorization_claimed
apply_authorization_consumed
apply_dispatching
prepared_unverified
rollback_pending
rollback_authorization_pending
rollback_authorization_claimed
rollback_authorization_consumed
rollback_dispatching
rolled_back_clean
recovery_required
```

Before every possible host call, the controller durably records the exact
pending authorization and atomically claims that request. Claimed is a
monotonic settlement fence: `resolve`, optional `consume`, and a second
`resolve` must converge on one exact `AuthorizationOutcome`. Pending or
unavailable settlement leaves the claim unchanged. A live generic recovery
transition cannot clear claimed state; semantic replay still accepts the
earlier canonical claimed-to-recovery history so existing databases remain
readable. A consumption is recorded before preflight and dispatch. A rejection
records `authorization.rejected` and enters `recovery_required` without a host
observation, attempt, or effect. No host preflight or effect occurs before
terminal settlement.

Only a caller with direct exception-free transition ownership calls the one
closed effect method; an exception-reconciled post-state is always non-owner.
After consumed settlement, the full host projection is checked before dispatch
and after the possible call, even when the method raises. A resumed dispatching
state observes but never invokes the effect again. A possible effect therefore
requires observation and a fresh authorization before any later attempt.

Precondition, postcondition, foreign, and unavailable observations are
distinct durable outcomes. Reconciliation never writes. Rollback is never
automatic: it derives only from the proven applied prefix, reverses only
closed compensations, and consumes a fresh exact authorization for each one.
Foreign or pre-existing resources are neither adopted nor deleted; unresolved
drift ends in `recovery_required`. The operation-specific host-scope lease is
released only after reusable whole-host `rolled_back_clean` proof. Recovery
events remain durable history, while the active recovery reason is cleared
only by that terminal proof.

## Historical ADR-0050-B bounded gates

The following 81-test result is the exact publication gate for Stage B before
the additive Studio Stage-C bridge existed. It remains historical evidence,
not the current A/B/C compatibility count.

### Provider-evidence selector

```text
PYTHONPATH=src python3 -m unittest \
  tests.test_ollama_observed_evidence_v2 \
  tests.test_ollama_v2_controller_contracts \
  tests.test_ollama_v2_controller_store \
  tests.test_ollama_v2_controller
Ran 81 tests in 11.401s
OK
```

### Known non-native Studio compatibility selectors

```text
PYTHONPATH=src python3 -m unittest \
  tests.test_studio_agent_harness_approval_bridge
Ran 46 tests in 12.058s
OK
```

```text
PYTHONPATH=src python3 -m unittest \
  tests.test_studio_authenticated_human_decisions
Ran 72 tests in 75.355s
OK
```

An earlier run of the second selector was terminated only by an artificial
60-second command timeout after 45 progress dots. The exact same selector was
rerun without that timeout and passed 72/72. The final publication-review gate
also passed 72/72 with a 180-second timeout allowance; this was
not a product failure.

### Explicit safe contract selector

Before execution, `tests/test_agent_harness_contracts.py` was inspected: its
imports are limited to copying, hashing, JSON, unittest, `Path`, the pure
Harness contracts, and the contract catalog. Its 29 named cases validate
fixtures, canonical documents, schemas, numeric rules, hashes, and catalog
coverage; it contains no native-launch, subprocess, systemd, or socket case.

```text
PYTHONPATH=src python3 -m unittest tests.test_agent_harness_contracts
Ran 29 tests in 0.066s
OK
```

### Runtime AI-import audit

```text
OK runtime=src/isoworld ai_imports=0
```

### Compilation

The three new implementation modules and three focused test modules compiled
successfully with every bytecode destination explicitly under `/tmp`:

```text
OK compiled=6 destination=/tmp/world-forge-adr0050b-final-pyc
```

### Protected public-byte comparison

`git diff --exit-code HEAD -- ...` reported no difference for
`provider_evidence/__init__.py`, `provider_evidence/ollama_v2.py`, the public
Harness package/contracts/catalog, `src/isoworld`, `schemas`, or `examples`:

```text
OK protected public bytes unchanged
```

`git diff --check` also passed.

### Identity check-only

The delegated writer ran check-only mode only and did not use generator write
mode. After the complete diff passed independent review, the root publisher ran
canonical generation. Generation and the immediate check-only verification
both reported:

```text
legacy identity allowlist: entries=306 occurrences=1072
```

Counts remained unchanged; generator-owned file hashes moved to the reviewed
ADR-0050-B bytes.

The final concurrent-ownership remediation used check-only mode again and
reported the same `306` entries and `1072` occurrences; no generator write ran
in the delegated writer.

One additional execution incident is recorded separately from TDD: an initial
Round-2 GREEN command used the nonexistent class name
`OllamaV2ControllerTests`, so unittest stopped at loader error without running
product code. A fresh read-only incident audit compiled the four assigned files,
identified the exact `ControllerStateMachineTests` selectors, and reproduced a
separate nonterminal rollback defect: the live transition and semantic replay
temporarily invented `host_state_not_reusable` during ordinary cleanup. Both
paths now preserve the active reason until terminal proof, and the corrected
targeted selector plus the complete controller module passed.

During the distinct-operation rollback triangulation, the new blocking fake
initially never reached its barrier because the shared test fake projected every
effect with the old literal operation ID `op-controller`. Operation-bound
capability validation correctly rejected that fake call, and the controller
observed no effect. The fake was corrected to use its bound plan's operation ID,
after which the barrier test proved the intended lease behavior. This was a
test-fixture defect, not native execution or a host mutation.

## Historical stage matrix at Stage-B publication

This table records the naming and state at the original Stage-B boundary. The
current seven-stage release-train matrix follows it below.

| ADR-0050 stage | Status after these gates |
|---|---|
| A — corrected pure contract foundation | **COMPLETE** |
| B — deterministic non-native controller core | **COMPLETE** |
| C — concrete privileged interpreter and exact broker/ExecStart authority | **ABSENT** |
| D — Studio Director Store/protocol/UI v7 authority | **ABSENT** |
| E — governed host preparation | **ABSENT** |
| F — native observed evidence and real inference | **ABSENT** |
| Overall ADR-0050 | **PARTIAL**, unavailable, non-production |

## Historical pre-settlement A/B/C compatibility update

The additive Stage-C consumption-parity remediation previously reran the
complete four-module foundation/controller selection before terminal rejection
settlement existed:

```text
PYTHONPATH=src python3 -m unittest \
  tests.test_ollama_observed_evidence_v2 \
  tests.test_ollama_v2_controller_contracts \
  tests.test_ollama_v2_controller_store \
  tests.test_ollama_v2_controller
Ran 83 tests in 11.486s
OK
```

The added controller regression resumes a durable consumed authorization
through the real state-machine path. Before any APPLY or ROLLBACK dispatch it
requires an exact-type resolver result and complete equality with the durable
ControllerStore consumption. An equal detached copy succeeds; foreign
authority or decision provenance and subclass results fail before another
controller event, attempt, or effect. The resolver target remains the one
captured at controller construction despite later instance or class
replacement.

That 83-test count is historical. It must not be read as the final controller
selection for the settlement candidate.

## Current controller settlement update

The final three-module controller selection, excluding the separately preserved
14-test pure foundation suite, passed:

```text
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m unittest \
  tests.test_ollama_v2_controller_contracts \
  tests.test_ollama_v2_controller_store \
  tests.test_ollama_v2_controller
Ran 79 tests
OK
```

The additive cases cover the exact canonical rejection outcome, durable APPLY
and ROLLBACK rejection events, the monotonic claimed settlement fence,
settlement pending/unavailable immutability, lost consume-reply resolution,
prohibition of live generic claimed recovery, readable legacy claimed-recovery
history, no preflight/effect before settlement, and captured-call replacement
resistance. Rejected requests create no effect attempt and never invoke the
test-local host port.

| Current ADR-0050 stage | Status |
|---|---|
| A — corrected v2 policy foundation | **COMPLETE** |
| B — deterministic non-native controller core | **COMPLETE** |
| C — backend Studio plan authorization and closed controller bridge | **COMPLETE** |
| D — concrete closed host interpreter/broker | **ABSENT** |
| E — Studio protocol, Electron IPC, and UI ceremony | **ABSENT** |
| F — separately authorized host preparation | **ABSENT** |
| G — native observed evidence and bounded real inference | **ABSENT** |
| Overall ADR-0050 | **PARTIAL**, unavailable, non-production |

## Historical Stage-B root publication steps

The following checklist was completed when Stage B was published as
`c2c86621842c45f79c2ad5730d91adb4b2f1b9c7`; it is retained as provenance, not
as an instruction for the current Stage-C candidate.

1. Review the complete dirty diff against
   `211d52f4e8fd20f40e5cbceda7584b3ce8129bf9` in a fresh read-only context.
2. At Stage-B publication, canonical generation and check-only both reported
   `306` entries and `1072` occurrences.
3. Only if later root-owned edits make that check stale, run the canonical
   generator in authorized write mode once and immediately recheck; never
   hand-edit the allowlist.
4. Run a final fresh independent read-only review of the complete diff and
   bounded gates.
5. Only the root publisher may stage, conventionally commit, and push.

The current Stage-C identity check is intentionally recorded in the Studio
settlement evidence rather than inferred from this historical checklist.

Until the currently absent stages are completed, this work is not native
Ollama evidence, not availability, not a provider PASS, and not production
readiness.
