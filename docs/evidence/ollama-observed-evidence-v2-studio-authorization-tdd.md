# Ollama observed evidence v2 — Studio settlement TDD evidence

- Date: 2026-09-02
- Base revision: `c2c86621842c45f79c2ad5730d91adb4b2f1b9c7`
- Scope: ADR-0050-C backend-only finite-plan authorization and terminal settlement
- Result: stages A/B/C **COMPLETE** as non-native backend logic; ADR-0050 overall **PARTIAL**
- Availability: `unavailable`
- Production eligibility: `false`
- Native/provider claim: **none**

## Candidate identity and safety boundary

The final candidate contains 28 dirty paths relative to the base revision:
22 modified and six untracked. They divide into six documentation files and 22
Python implementation/test files. The untracked process-recovery gate is
`tests/test_studio_ollama_v2_authorization_process_recovery.py`; it is included
in that exact inventory rather than treated as external evidence.

No full test discovery, network access, dependency installation, provider or
model execution, native Ollama process, systemd/service/socket/account action,
host mutation, identity-generator write, staging, commit, or push was used for
this record. SQLite databases and test-local effect files lived under temporary
directories. Test doubles prove only backend control flow.

The public Studio protocol remains v6. Electron main, preload, renderer, and UI
are unchanged. The ProviderAdapter catalog still has only the two existing
synthetic runtimes; Ollama is not admitted.

## Delivered settlement architecture

### Controller claimed state is a monotonic settlement fence

`AuthorizationOutcome` is the exact union of
`AuthorizationConsumption | AuthorizationRejection`. A rejection is a frozen,
canonical request-bound document containing the exact operation, plan, effect,
phase, attempt, generation, sequence, head, ownership, policy, interpreter,
Studio authority, mandate, decision, slot, effect hash, rejection reason, and
authenticated settlement-event identity. Its closed reasons are `revoked`,
`expired`, and `denied`.

After `authorization.pending`, the ControllerStore durably records
`authorization.claimed`. From that point the controller:

1. calls the captured `resolve` target;
2. if no outcome exists, calls the captured `consume` target;
3. calls `resolve` again; and
4. accepts only one exact canonical outcome equal to any returned value.

Pending or unavailable settlement leaves the exact claimed operation,
authorization row, and event history unchanged. A live generic
`record_recovery` cannot clear either APPLY or ROLLBACK claimed state. Semantic
replay still accepts the earlier canonical claimed-to-recovery event shape so a
legacy ControllerStore remains readable; that compatibility does not reopen the
live transition.

A consumed outcome is durably recorded before host preflight. A rejected
outcome is durably recorded as `authorization.rejected` and moves the operation
directly to `recovery_required`. No host observation, effect-attempt row, or
effect call exists before terminal settlement. The controller therefore cannot
escape an uncertain claim by guessing recovery and cannot execute while the
outcome is unknown.

### StudioStore schema v8 owns exclusive terminal outcomes

Schema v8 retains the v6 authenticated-human authority and v7 mandate concepts,
then adds these exact settlement properties:

- mandate states are `prepared`, `approved`, `denied`, `revoked`, or `expired`;
- authenticated events add `rejected`, whose slot semantics match `consumed`;
- `studio_ollama_v2_authorization_outcomes` stores exactly one `consumed` or
  `rejected` outcome per mandate slot/effect and controller authorization/request;
- every consumed outcome has exactly one matching row in the retained
  consumption projection, while every rejected outcome has no consumption row;
- outcome, event, request, authorization, slot, effect, and optional
  consumption identities are independently unique; and
- replay reconstructs the mandate projection, consumption projection, and
  terminal outcome ledger from exact authenticated events and requires their
  complete bijection.

When an exact claimed request meets a revoked mandate, or an approved mandate
expires, Studio appends one authenticated `rejected` event, records one
canonical `AuthorizationRejection`, retains the consumed cursor, and makes
expiry durable as state `expired`. A rejected slot is settled but is never a
consumption and never authorizes a later slot. A denied mandate never binds and
creates no controller claim or outcome.

Primary v7-to-v8 migration runs under one savepoint. It verifies the exact v7
input, renames and rebuilds the three mandate tables, creates the outcome
ledger, copies every row, and backfills every legacy consumption through its
exact authenticated consumed event. It verifies the complete v8 schema,
consumed-projection bijection, and backfill count before publishing version 8.
Ordinary exceptions and `BaseException` restore the exact data-bearing v7
database. A secondary Store requires exact v8 and refuses v7; it never migrates
or backfills.

### Exact controller/Studio settlement and rebind

One approved mandate still binds one finite contiguous remaining APPLY or
ROLLBACK scope and one nonrefundable slot per exact effect. Apply never implies
rollback. The impact is derived from the canonical controller plan and carries
no caller-supplied path, permission, egress, cost, or production claim.

The concrete port exposes exactly `consume` and `resolve`. Construction requires
the exact already-open ControllerStore object and operation ID and captures its
private custody and read targets. Binding derives the current slot ordinal from
the phase cursor minus the mandate's starting cursor; it never trusts the Studio
consumed counter to choose a Controller effect.

The only continuable Controller states are phase pending,
authorization-pending, authorization-claimed, authorization-consumed, and
dispatching. Each completed prior slot must have exactly these five contiguous
transitions:

1. `authorization.pending`;
2. `authorization.claimed`;
3. `authorization.consumed`;
4. `effect.dispatching`; and
5. `effect.observed`.

Generation, sequence, event count, and cursor must equal the derived ordinal's
complete cycles plus the exact current-state offset. Every request, outcome,
attempt, binding, before/after snapshot, effect identity/hash, and ownership
field is rehydrated. Each prior Controller consumption must equal the Studio
consumed outcome at the same slot. The current slot must contain exactly the
prefix permitted by its state; claimed additionally permits the one exact
Studio outcome written before a lost settlement reply. Extra, missing, foreign,
or reordered history fails closed.

The controller's private attachment callback then rereads the complete
snapshot, plan, rollback plan, current request/outcome, and attachment proof and
requires equality with the bind-time read before enabling the port. Every port
call still proves its exact live request in a completed ControllerStore read
transaction before Studio begins one. Compatible counters, nonzero heads,
copied Stores/ports, subclasses, method replacement, other connections, or
another operation cannot mint authority.

`consume` atomically writes either terminal outcome. `resolve` is read-only and
returns only that exact durable outcome. Rebind never searches for a compatible
or latest authority, refunds a slot, or repeats settlement. Pending,
authorization-pending, claimed, and consumed resume normally; an
exception-reconciled non-owner stops at the exact durable post-state.
Dispatching is strictly observe-only and cannot invoke the effect again.
Controller-B independently requires exact full-value parity for a durable
consumption before dispatch. A foreign authority, decision, derived identity,
or other field produces no Studio mutation, attempt, or test-local effect.

The same private authority `RLock`, `BEGIN IMMEDIATE`, exact consumed cursor,
and outcome uniqueness make settlement versus revoke/expiry a single-winner
CAS. Exact built-in JSON/SQLite scalar and container types plus safe integers
are verified before semantic equality; rehashing and re-MACing a boolean or
integral float cannot impersonate an integer transition.

## Strict TDD settlement tranches

| Tranche | Genuine RED | GREEN | Triangulation |
|---|---|---|---|
| Controller terminal outcome | Claimed requests could only consume or escape through generic recovery; revoked/expired outcomes had no exact controller contract | Added canonical rejection, outcome normalization, durable rejection transition, and claimed recovery fence | APPLY/ROLLBACK consumed and rejected outcomes, pending/unavailable immutability, lost reply, live recovery refusal, legacy replay, captured targets, and zero preflight/effect before settlement |
| Studio schema-v8 settlement | Revoked/expired claims could remain ambiguous and v7 had no exclusive outcome row | Added durable expired state, authenticated rejected events, exclusive outcomes ledger, consumed projection bijection, and idempotent consume/resolve | Rejection commit pre/post/third-state, races, exact replay/tamper, foreign parity, and consumed/rejected exclusivity |
| v7-to-v8 migration | A data-bearing v7 Store had no terminal-outcome table or backfill | One savepoint rebuilds and verifies v8 before version publication | Fresh-v8 shape equality, legacy consumption backfill, `Exception`/`BaseException` rollback, and secondary-v7 refusal |
| Fresh-process saga | Same-process close/reopen could not prove interpreter exit released SQLite ownership or that post-crash reconciliation stayed at-most-once | Added a stdlib-only abrupt-exit/recovery/audit harness | Eight balanced APPLY/ROLLBACK cutpoints plus denied; the pre-ladder source passed three complete loops |
| Finite-plan restartability | Rebinding only a single claim/outcome could not prove a mandate survived every intermediate state or more than one slot | Derived the current slot from the Controller cursor, verified all prior five-transition cycles and exact Studio outcomes, and reread the proof during attachment | Fresh-process nine-effect APPLY and ROLLBACK ladders rebind pending, authorization-pending, claimed, consumed, and dispatching; dispatching observes without redispatch |

Earlier 29-, 32-, 35-, 37-, 40-, and 42-test Stage-C tranche counts, and the
83-test pre-settlement foundation/controller run, are historical development
evidence. They are deliberately not labeled as final gates below.

## Fresh OS-process SQLite saga gates

The source identity is:

```text
76dafeb313db4dc56ab7b671b96db3dfa60b7397a1604cd2d9d82733c935e1f5  tests/test_studio_ollama_v2_authorization_process_recovery.py
```

The current module has 11 tests: the nine settlement-cutpoint/control cases
below and two full finite-plan restart ladders.

### Settlement cutpoint matrix

The unittest parent never opens either Store. Each of the eight crash cases uses
three independent `sys.executable -B` children: one abrupt-exit child, one fresh
recovery child, and one fresh audit child. The denied control is a separate
child and proves no claim, outcome, or effect exists.

| Durable boundary | APPLY case | ROLLBACK case |
|---|---|---|
| Controller claim committed | consumed | revoked rejection |
| Studio transaction immediately before `COMMIT` | expired rejection | consumed |
| Studio commit complete but wrapper has not returned | consumed | expired rejection |
| Controller outcome acknowledgement committed | revoked rejection | consumed |

The `studio_pre` cutpoint observes the uncommitted outcome inside the transaction
and exits immediately before calling SQLite `COMMIT`. The `studio_post` cutpoint
calls `COMMIT` and exits immediately after it returns but before the wrapper can
return success. Controller claim and acknowledgement cutpoints likewise occur
after their commit returns. These brackets do **not** interrupt inside SQLite
`COMMIT` and do not emulate kernel, storage-device, or power-loss failure.

Recovery and audit independently reopen both databases, replay both histories,
and verify:

- exactly one Studio outcome and the equal ControllerStore outcome;
- consumed projection equality for consumption and its absence for rejection;
- exactly one authenticated rejected event for rejection;
- one dispatch attempt and one test-local effect for consumption, zero for rejection;
- exact controller state, cursor, lease, event sequence, and stable database fingerprint;
- zero duplicate settlement/effect during recovery or audit; and
- both SQLite locks are acquirable after the crash process exits.

This is genuine OS-process-exit/reopen evidence for the SQLite saga. Three
complete nine-test loops previously passed 27/27 against the pre-ladder source
identity
`51b10925923efd4d9245c70aee74b67de97debaa780e5b2c07771a12eba3ba47`.
That result is retained as historical settlement-boundary evidence, not as the
final current process-module count or hash. It is not
mid-commit durability, power-loss, filesystem-crash, native Ollama, systemd,
service, host-preparation, provider, model-load, or inference evidence.

### Full finite-plan restart ladders

The two current ladder tests cover one nine-effect APPLY mandate and one
nine-effect ROLLBACK mandate. For each slot a new interpreter binds and resumes
from each source state in order: phase pending, authorization-pending, claimed,
consumed, and dispatching. The first three transition children commit one
Controller transition and lose the reply after commit. The dispatch child
records one test-local effect marker and exits abruptly while the durable state
is dispatching. A new child binds that state, performs observation only, and
advances the cursor without redispatch.

The final independent audit requires:

- `prepared_unverified` after all nine APPLY effects;
- `rolled_back_clean` and no host-scope lease after all nine ROLLBACK effects;
- nine exact Controller/Studio consumption outcomes and an exhausted mandate;
- nine postcondition attempts, nine distinct effect markers, and no duplicate;
- one complete five-event Controller cycle for every effect; and
- both SQLite transaction locks acquirable after all child exits.

The ladders prove complete finite-plan process restartability for the
test-local Controller/Studio SQLite saga. They do not prove interruption inside
SQLite `COMMIT`, power-loss durability, a native Ollama process, service or host
mutation, provider execution, model load, or inference.

## Current bounded gates

The current implementation-writer selections reported these exact counts
against the same 28-path candidate. Timings from the earlier settlement-only
candidate are not relabeled as current.

### Studio core

```text
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m unittest \
  tests.test_studio_storage \
  tests.test_studio_ollama_v2_authorization_contracts \
  tests.test_studio_ollama_v2_authorizations
Ran 71 tests
OK
```

### Controller settlement

```text
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m unittest \
  tests.test_ollama_v2_controller_contracts \
  tests.test_ollama_v2_controller_store \
  tests.test_ollama_v2_controller
Ran 79 tests
OK
```

### Foundation and Studio compatibility

```text
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m unittest \
  tests.test_ollama_observed_evidence_v2 \
  tests.test_studio_storage \
  tests.test_studio_authenticated_human_decisions \
  tests.test_studio_director_control
Ran 116 tests
OK
```

### Authorization domain and current process module

The implementation-writer domain/process selection passed 56 tests: 45 Studio
authorization-domain tests plus all 11 current process tests. The delegated
documentation writer then reran the six contract tests with those same domain
and process modules, so the current process source was executed once in this
final documentation pass:

```text
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m unittest \
  tests.test_studio_ollama_v2_authorization_contracts \
  tests.test_studio_ollama_v2_authorizations \
  tests.test_studio_ollama_v2_authorization_process_recovery
Ran 62 tests in 213.053s
OK
```

The module census is therefore six contracts + 45 domain + 11 process = 62.
The two exact full-ladder selectors also passed 2/2 and are included in the
11-test process module.

### Current protocol compatibility

```text
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m unittest \
  tests.test_studio_protocol_v5 \
  tests.test_studio_protocol_v6
Ran 20 tests
OK
```

The earlier five migration selectors, 46-test Studio-to-Harness bridge, and
eight schema-pin selectors remain historical settlement-candidate evidence;
they are not presented as current restartability reruns.

The protocol-v6 bytes remain exact:

```text
66bc9157f7dc07b1229f194b5606571ea5c83f4ff2d770ba83a74a7099bc2e73  schemas/studio-protocol-v6.schema.json
77cbdc3857944e39e86e70be9da9987b3928c5c26314452ddc62554edc7508f6  apps/studio/src/generated/studio-protocol-v6.d.ts
```

Before the additive restartability tranche, all 22 changed or untracked Python
files compiled with bytecode directed to
`/tmp/world-forge-adr0050c-docsettlement-pyc`, and the unchanged runtime audit
reported:

```text
OK compiled=22 destination=/tmp/world-forge-adr0050c-docsettlement-pyc
OK runtime=src/isoworld ai_imports=0
```

A current protected-byte comparison against the base finds no change under the
Studio app and public protocol/service boundary, public Harness package/
contracts/schemas/fixtures, `src/isoworld`, the pure Ollama-v2 foundation
module, or its package initializer. The two protocol-v6 hashes above also remain
exact against the base.

Tracked and untracked whitespace checks and local Markdown-link/static checks
pass after this reconciliation. Identity check-only remains the one expected
publication blocker: the generator-owned allowlist still binds the pre-C
README bytes. Check-only reported expected hash
`4ea28b883656dba3dcc543a87b92066aed61a49752964093b64a131cb14a1fd6`
and observed hash
`701051c802affe30ecccc16d54601a07e304a64f44d2f1c1925cd240b31fdd14`.
The full diagnostic is intentionally not reproduced because its governed
identity token is itself subject to the same allowlist.

No allowlist write was performed by this delegated writer. Canonical root-owned
generation and immediate check-only verification remain required after final
review; the allowlist must never be hand-edited.

## Release-train state

| ADR-0050 stage | State |
|---|---|
| A — corrected v2 policy foundation | **COMPLETE** |
| B — deterministic non-native controller core | **COMPLETE** |
| C — backend Studio plan authorization and terminal settlement bridge | **COMPLETE** |
| D — concrete closed host interpreter/broker | **ABSENT** |
| E — Studio protocol, Electron IPC, and UI ceremony | **ABSENT** |
| F — separately authorized host preparation | **ABSENT** |
| G — native observed evidence and bounded real inference | **ABSENT** |
| Overall ADR-0050 | **PARTIAL**, unavailable, non-production |

Concrete host interpreter/broker, Studio protocol/UI ceremony, host
preparation, systemd/account/socket/service/model mutation, native observation,
real inference, provider/catalog admission, public receipt, production
eligibility, and availability remain absent.
