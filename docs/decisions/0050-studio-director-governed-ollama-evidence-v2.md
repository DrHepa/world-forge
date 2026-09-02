# ADR-0050: Correct Studio Director-governed observed Ollama evidence as v2

- Status: accepted; implementation partial
- Date: 2026-09-01

## Context

ADR-0046 specified a non-production observed Ollama evidence target. It remains
an immutable historical decision whose exact bytes have SHA-256
`bc4117aa580834984b4847ddb3a81180c6b14f99ba7954f1959abba8f27fbf42`.
Its ordered 86-row vocabulary table, isolated from prose and hashed as the exact
LF-terminated sequence of IDs, has SHA-256
`518cdc4056f8d4ad3cfa9a28b08dcf2324c4b3833f4bc04fd49a9e8b2bc06ed9`.
The prose deliberately names the forbidden
`worldforge_ollama_evidence_custody_handoff_v1` alias outside that table, so a
whole-document search is not a valid registry check.

Subsequent static inspection invalidated three assumptions required by that
target:

1. an empty transient `SupplementaryGroups` assignment does not prove that
   name-service supplementary groups were excluded from the ambient `ollama`
   principal;
2. the ambient executable and model roots were neither copied into dedicated
   World Forge custody nor proven sealed against writable, symlink, or hardlink
   final roots; and
3. the reviewed systemd 255 manager did not provide the proposed transient
   `StandardInputFileDescriptor:h` setter. Its observed descriptor-name property
   cannot substitute for an input setter.

Those are contract defects, not failed provider executions. No service, model,
socket, host account, systemd unit, or inference was touched to reach this
decision.

## Decision

### ADR-0046/v1 is permanently unavailable

The canonical
`world-forge.private.ollama_adr0046_disposition` version-2 correction document
binds the exact ADR bytes, ordered registry, and these exhaustive defect codes:

- `ambient_model_root_custody_unsealed`
- `ambient_release_root_custody_unsealed`
- `nss_supplementary_groups_not_excluded`
- `transient_standard_input_fd_setter_unavailable`

Its availability is permanently `permanently_unavailable`. Production
eligibility, catalog admission, provider execution, provider turns, replay
claims, and pricing claims are false. Migration, conversion, and promotion are
also false: no v1 document or evidence can become v2 evidence. The canonical
content hash is
`ec2fa718852dfc55babd1de180a0e799a87e2542555b231fa88f080873c2e99a`;
the SHA-256 of its complete compact canonical bytes is
`b2367c785c7435d678421fe0abfff2b2a583f123081d3adfbef5255a3642b05d`.

### The v2 foundation policy is a closed immutable document

The canonical
`world-forge.private.ollama_observed_evidence_foundation_policy` version-2
document defines only a correction policy:

- the principal and primary group are exactly `worldforge-ollama-evidence`;
  it is a dedicated non-login principal, admits neither the ambient `ollama`
  account nor name-service supplementary groups, and has no supplementary
  groups; `render` and `video` are explicitly forbidden;
- executable release and model custody each require a copied, byte-manifested,
  sealed World Forge root; ambient, symlink, hardlink, and writable final roots
  are forbidden;
- socket activation uses installed
  `worldforge-ollama-evidence.socket` and
  `worldforge-ollama-evidence.service` units. The socket's exact
  `FileDescriptorName=ollama-http` must match the service's exact
  `StandardInput=fd:ollama-http`; a transient FD setter is forbidden;
- `OLLAMA_NO_CLOUD=1` is exact, parent environment inheritance is forbidden,
  and the listener is numeric IPv4 loopback `127.0.0.1` only. DNS,
  non-loopback addresses, redirects, proxies, and proxy-environment inheritance
  are forbidden;
- the device profile is exactly CPU-only with no accelerator. Supplementary
  accelerator groups, device allow entries, accelerator paths, selected
  accelerator backends, runtime activation, device open, mmap, and ioctl are
  all forbidden; and
- availability remains `unavailable`; production eligibility, catalog
  admission, provider execution, provider turns, replay claims, and pricing
  claims remain false.

The canonical content hash is
`c4fbf98a52896901bb46732935a7fbef462b7369105dab5bffcff381a3968f73`;
the SHA-256 of its complete compact canonical bytes is
`030f2a3432efc21d3f9915cd39575e334c47b24b58770935c5105e8f5d5c1322`.
Validators require exact JSON types and fields, reject bool-as-int and
non-JSON values, validate the outer content hash, and then require byte identity
with the applicable canonical document. The v1 and v2 formats never
cross-accept.

### The foundation release is deliberately pure and contract-only

`worldforge.provider_evidence.ollama_v2` accepts supplied bytes or JSON values
and performs deterministic validation only. It imports no Harness, provider
catalog, worker, EventLog, filesystem, process, socket, systemd, network, model,
SDK, or Studio implementation. It creates no public schema, receipt, catalog
entry, `ProviderAdapter`, worker identity, or runtime effect.

The existing synthetic catalog therefore remains exactly two entries:
`worldforge_conformance_provider` revision 4 and
`worldforge_deterministic_probe_provider` revision 6, both protocol version 3
and non-production. Ollama is not a third entry.

### The controller core is real transaction logic but still non-native

The second release boundary adds three private modules under
`worldforge.provider_evidence` without changing the pure `ollama_v2.py`
foundation:

- `ollama_v2_controller_contracts.py` owns frozen, slotted, exact
  JSON-compatible contracts for the interpreter binding, bounded tree
  manifests, principal/unit/host observations, effects, plans, one-use
  authorizations, operations, and rollback. It binds policy content hash
  `c4fbf98a52896901bb46732935a7fbef462b7369105dab5bffcff381a3968f73`
  and serialized SHA-256
  `030f2a3432efc21d3f9915cd39575e334c47b24b58770935c5105e8f5d5c1322`,
  fixed numeric UID/GID `9731`, code-owned roots, the unit directory, and
  exact interpreter-contract and unit bytes. Tree inputs are bounded and
  reject malformed paths, Unicode/case-fold collisions, overlaps, links, and
  writable final entries. UID-owner and GID-owner censuses are independent, so
  either numeric collision is observable and rejected without inventing the
  other or adopting either identity.
- `ollama_v2_controller_store.py` is a private exact-schema SQLite store. It is
  independent of Studio Store and Agent Harness EventLog, uses
  `BEGIN IMMEDIATE`, foreign keys, generation/sequence/head/state CAS,
  canonical stored documents, an event hash chain, unique authorization and
  effect-attempt identities, and one durable lease for the fixed host scope.
  Every plan, effect, authorization, owned resource, attempt, and lease carries
  the operation-specific ownership token. Every mutation returns whether that
  caller completed a direct, exception-free commit. An exact duplicate returns
  non-owner, and an exact post-state found after any commit exception also
  returns non-owner: adjacent state equivalence proves durability but cannot
  prove which concurrent caller committed it. Only a direct commit owner may
  settle authorization or dispatch. Event payloads bind exact request,
  consumed-or-rejected outcome, attempt, projection, ownership, and rollback
  hashes. A
  zero-effect cleanup event additionally binds the complete observed clean
  snapshot. Reopen
  semantically replays every transition and requires a bijection with every
  authorization and attempt row, rejecting orphan, missing, extra, rewritten,
  or misclassified auxiliary evidence. A commit exception accepts only an exact
  complete pre-state or exact complete immediate post-state; any third state
  poisons the operation and requires recovery. This does not protect against a
  coherent database rollback by the same OS principal.
- `ollama_v2_controller.py` captures every inspector, authorization, store,
  and host-effect call target at construction. Its ports are closed:
  inspection has only `inspect`/`observe`, authorization has only
  `consume`/`resolve`, and each effect has one named method. There is no shell,
  argv, generic command, generic RPC, or provider execution surface.

The deterministic apply plan has this exact order and no caller-selected
command/unit/environment payload:

1. `managed_root.create`
2. `principal.create_exact`
3. `release.stage`
4. `release.publish`
5. `model.stage`
6. `model.publish`
7. `socket.install`
8. `service.install`
9. `manager.reload`

Before every host call, the controller durably records an exact pending
authorization, atomically claims that pending request, and settles the claim to
one exact consumed-or-rejected `AuthorizationOutcome`. Claimed is monotonic:
pending/unavailable settlement leaves it unchanged, and a live generic recovery
transition cannot clear it. Historical claimed-to-recovery events remain
readable through semantic replay. Rejection is durable and reaches
`recovery_required` without host preflight or an effect attempt. Consumption is
durable before the controller verifies the complete exact host projection for
the applied/remaining prefix and marks the attempt dispatching. Only a caller whose relevant
transition returned direct exception-free commit ownership may perform the
corresponding external action. An exception-reconciled exact post-state returns
the durable snapshot but never execution ownership. It always observes the
complete projection after a possible host call, including a raised call, and
classifies the result as exact precondition, exact postcondition, or foreign.
Drift in any prior, current, remaining, cleaned, or retained resource therefore
stops dispatch before a later resource can hide it. An unresolved dispatch is
observed rather than retried. A no-effect result can retry only with a new
authorization identity. `reconcile` is read-only.

Rollback is explicit, never automatic. It derives reverse compensations only
from the exact prefix of effects proven applied, requires a fresh one-use
authorization per compensation, and observes ownership/preconditions before
dispatch. It neither adopts nor deletes pre-existing or foreign resources.
Existing drift remains recorded, and cleanup that cannot be proven exact ends
in `recovery_required` rather than a clean claim. The fixed-scope lease remains
held through prepared and recovery states. Rollback manager reload clears the
operation ownership marker while advancing its generation monotonically. A
terminal transition may clear the active recovery reason and release the lease
only after one complete reusable-host projection proves that all resources
match the initial clean projection, no manager ownership marker remains, and
the manager generation has not moved backwards. Historical recovery events
remain in the hash chain. `rolled_back_clean` is immutable: it cannot re-enter
apply, rollback, or recovery after releasing the lease. Live transitions reject
that source state before mutation, and semantic replay rejects a canonical
recovery event appended after the terminal even if a forged lease is restored.
A second operation cannot credit or delete the first operation's resources.

This controller has no concrete host interpreter. Its terminal apply state is
only `prepared_unverified`; that state is not observed evidence, availability,
PASS, provider readiness, or production readiness. Test-local effect fakes
prove controller behavior only and are not systemd, account, socket, model, or
native evidence.

### Studio backend authorizes and settles finite plans without a host interpreter

StudioStore schema v8 owns the private
`studio_ollama_v2_authorization_*` decision, consumption, authenticated-event,
and terminal-outcome domain. It reuses the one exact `director_local`
credential, verifier, Store-owned connection and `RLock`, and event key. A
distinct MAC message-domain prefix prevents an Ollama mandate event from being
transplanted into the older Agent Harness approval chain. The authenticated
human-decision sub-schema remains at version 6. Schema v7 remains the exact
legacy mandate input to an atomic primary v7-to-v8 migration; secondary stores
require v8 and never migrate.

The v8 migration rebuilds the three v7 mandate tables, creates the exclusive
outcome ledger, copies every exact row, backfills every legacy consumed slot
through its authenticated consumed event, and verifies the complete schema and
consumed-projection bijection before publishing version 8. `Exception` and
`BaseException` paths restore the exact data-bearing v7 database. A secondary
attachment refuses v7 rather than acquiring authority by migration.

One approved mandate covers exactly one finite remaining apply or rollback
scope. Its canonical review rehydrates and binds the exact controller plan,
optional rollback plan, starting operation snapshot and cursor, ownership,
policy and interpreter hashes, and the contiguous ordered effect IDs and full
effect hashes. Its impact document is derived rather than caller supplied and
fixes manifest and resource ceilings, data destinations, closed permissions,
network egress as prohibited, pricing as not applicable, and every
production/catalog/provider/native/public/user-data claim as false. An empty
scope creates no authority. Exact Controller-B snapshots at the terminal apply
cursor and exact zero-effect rollback snapshots both rehydrate before reaching
that explicit rejection. Apply never implies rollback.

Approval grants one nonrefundable durable slot per effect. The closed
`StudioOllamaV2AuthorizationPort` has exactly `consume` and `resolve`, and both
return only the canonical `AuthorizationOutcome` union:
`AuthorizationConsumption` or `AuthorizationRejection`. The outcome ledger
permits exactly one terminal result for each mandate slot, effect, controller
authorization, and request. Every consumed outcome has one exact row in the
legacy consumption projection; every rejected outcome has none. Replay
reconstructs that bijection from authenticated `consumed` and `rejected`
events.

The Director binding API requires the exact already-open
`OllamaV2ControllerStore` instance and exact operation ID. Studio creates no
controller connection. The port captures that object's exact read/status
targets and private custody identities and revalidates them before every call.
Before settlement, a controller-only read transaction must prove the exact
phase-specific authorization-claimed operation state and the persisted
canonical request document/hash equal to the supplied request, including plan,
effect, phase, attempt, generation, sequence, head, policy, interpreter, and
ownership fields. No counter progression or nonzero-head heuristic grants a
slot.

Claimed is a monotonic controller settlement fence. The controller first calls
`resolve`; if no outcome exists it calls `consume`, then resolves again. Pending
or unavailable settlement leaves the claim byte-for-byte unchanged. A live
generic `record_recovery` cannot clear claimed state, although semantic replay
continues to read canonical claimed-to-recovery events created by the earlier
controller. No host preflight observation, effect-attempt row, or effect call
occurs before an exact outcome is durable. Consumed outcomes advance to
authorization-consumed; rejected outcomes record `authorization.rejected` and
move directly to `recovery_required` with no host call.

When a claimed request meets an already revoked or newly expired approved
mandate, Studio durably appends an authenticated `rejected` event, records a
canonical rejection bound to the exact mandate, decision, slot, effect,
request, and settlement event, and retains the consumed count. Expiry becomes
durable mandate state. Denied mandates never bind and create no controller
claim or outcome. Revocation and expiry never refund a consumed slot or
authorize another slot.

`resolve` is read-only and returns only the exact already durable outcome for
the same claimed, consumed, or rejected lineage. Controller-B independently
requires exact full-value parity between a resolved consumption and its durable
ControllerStore consumption before dispatch. A different authority, decision,
derived identity, or other field fails with no Studio mutation, attempt, or
host effect. Request-only `matches()` is not authorization provenance.

After Store reopen, binding derives the current mandate slot from the
Controller's phase cursor relative to the mandate starting cursor. It accepts
only the exact phase-pending, authorization-pending, claimed, consumed, or
dispatching state. Every prior slot must prove one complete contiguous cycle of
five Controller transitions—authorization pending, claimed, consumed, effect
dispatching, and effect observed—with its exact request, consumption, attempt,
event bindings, snapshots, effect hash, and equal Studio outcome. The current
slot must prove exactly the corresponding partial cycle, including any durable
Studio outcome already written before a lost reply. Foreign or extra history
fails closed; no compatible or latest authority is searched or adopted.

The exact reopened ControllerStore object must still complete the private
construction handshake. Attachment rereads and compares the entire bind-time
Controller proof before making the port usable. Pending, authorization-pending,
claimed, and consumed resume normally; an exception-reconciled non-owner stops
at the exact durable post-state. Dispatching is observation-only and never
repeats the effect. A commit-then-lost reply therefore resumes without
duplicating settlement, slot mutation, or dispatch. Foreign lineage, denied
mandates, unrelated recovery, and zero-outcome terminal mandates remain
ineligible.

Revoke additionally compares the exact consumed-slot cursor. Concurrent
settlement versus revoke or expiry therefore has one CAS owner; lock
invalidation waits on the same private authority `RLock`; and independently
opened, thread-owned connections converge through `BEGIN IMMEDIATE` and exact
outcome uniqueness. Replay requires exact built-in JSON/SQLite scalar and
container types plus safe integers before event, projection, consumption, or
outcome equality. A correctly rehashed and re-MACed boolean or integral float
cannot impersonate an integer field or a different transition class.

The fresh-process saga gate uses eight balanced APPLY/ROLLBACK cases and a
denied control. Every case runs an abrupt-exit child followed by independent
recovery and audit interpreter processes. Cutpoints are immediately before
Studio `COMMIT`, after commit but before the wrapper returns, after the
controller claim commit, and after the controller outcome-acknowledgement
commit. Before the ladders were added, three complete loops passed 27/27 tests
and proved one exact terminal outcome, controller/Studio equality, at-most-once
test-local effect, durable replay, and released SQLite locks after process exit.
That count belongs to the earlier process-source identity; the current module
retains those cases and has 11 tests. The gate does not interrupt inside SQLite
`COMMIT`, emulate power loss, or provide native Ollama, service, systemd, host,
or inference evidence.

Two further fresh-process tests traverse the complete nine-effect APPLY and
ROLLBACK finite plans. Every slot is rebound in a new interpreter from phase
pending, authorization-pending, claimed, consumed, and dispatching. Controller
transition commits lose their reply after commit; the dispatch child writes one
test-local marker and exits abruptly, and the next child resumes by observation
without another effect call. Independent final audits require nine exact
Controller/Studio outcome pairs, nine postcondition attempts, one full
five-event cycle and one marker per effect, released SQLite transaction locks,
and the exact terminal state: `prepared_unverified` for APPLY or
`rolled_back_clean` with lease deletion for ROLLBACK. These ladders add no
mid-`COMMIT`, power-loss, native/provider, service, host, or inference proof.

This release deliberately adds no Studio protocol method, Electron IPC,
preload/renderer surface, concrete interpreter, host execution, systemd or
account mutation, model access, provider turn, public receipt, catalog entry,
or native evidence. Controller integration tests use test-local inspector and
effect doubles only.

### ADR-0050 is one coupled release train, not one oversized commit

The exact implementation-stage matrix is:

| Stage | State | Authority gained |
|---|---|---|
| A — v2 correction-policy foundation | **COMPLETE** | Pure canonical policy validation only |
| B — deterministic controller contracts/store/state machine | **COMPLETE** | Private non-native transaction logic ending at `prepared_unverified` |
| C — backend Studio plan authorization and closed controller bridge | **COMPLETE** | Finite authenticated non-native apply/rollback mandates only |
| D — concrete closed host interpreter/broker | **ABSENT** | None; the binding says `native_implementation_state: absent` |
| E — Studio protocol, Electron IPC, and UI ceremony | **ABSENT** | None |
| F — separately authorized host preparation | **ABSENT** | None |
| G — native observed evidence and bounded real inference | **ABSENT** | None |

The overall ADR-0050 implementation therefore remains **PARTIAL**,
`availability: unavailable`, and `production_eligible: false`.

The shipped backend Studio authority binds an authenticated Director decision
to an exact controller plan without putting Ollama into the Harness catalog.
The later protocol/UI ceremony and host preparation remain absent. Host
preparation must use dedicated copied custody rather than mutate or adopt the
ambient installation. Native evidence must prove the installed socket/service
pair, exact principal/group census, sealed roots, cloud-off loopback route,
no-proxy state, CPU-only device boundary, cleanup, and a real bounded inference.
None of those later requirements is satisfied by the existence of this policy.

## Consequences

- ADR-0046 stays byte-for-byte unchanged and is permanently unavailable.
- The correction policy and controller transaction core are functional and
  deterministic. They still cannot launch a host interpreter, establish
  systemd/native observations, run inference, replay or price a provider turn,
  or promote availability.
- No synthetic fixture or contract test is native Ollama PASS evidence.
- ADR-0050 remains **PARTIAL**, with `availability: unavailable` and
  `production_eligible: false`, until every later boundary ships and receives
  its own evidence.
- Any future controller or Studio release must consume the exact canonical
  policy rather than restating weaker host assumptions.

## Verification

The strict-TDD record is
[`ollama-observed-evidence-v2-contract-tdd.md`](../evidence/ollama-observed-evidence-v2-contract-tdd.md).
It covers exact source/registry binding, canonical vectors, closed validation,
adversarial drift, package isolation, the unchanged two-entry synthetic
registry, and protected Harness/public bytes. It contains no service start,
process/socket/model execution, host mutation, network access, installation, or
synthetic native PASS claim.

The controller-core strict-TDD record is
[`ollama-observed-evidence-v2-controller-tdd.md`](../evidence/ollama-observed-evidence-v2-controller-tdd.md).
It covers exact contracts and hostile inputs, deterministic planning, every
durable transition and ambiguous-commit state, reopen/replay corruption,
one-use authorization, closed captured dispatch, mandatory observation,
read-only reconciliation, and explicit rollback. It performs no live
filesystem/systemd/account/service/socket/network/model/provider operation.

The backend Studio mandate record is
[`ollama-observed-evidence-v2-studio-authorization-tdd.md`](../evidence/ollama-observed-evidence-v2-studio-authorization-tdd.md).
It covers schema-v8 creation, atomic v7-to-v8 migration and backfill, the
exclusive consumed-or-rejected outcome ledger, canonical finite mandates,
authenticated decision/outcome replay, exact controller settlement and rebind,
apply/rollback separation, custody invalidation, commit ambiguity, and the
fresh-process SQLite saga gate. Its eight settlement crash paths plus denied
use independent crash/recovery/audit processes; its two full nine-effect
ladders rebind every continuable state through the terminal APPLY and ROLLBACK
outcomes. Neither form adds protocol, UI, mid-`COMMIT` or power-loss durability,
native Ollama, service, systemd, host, provider, or inference execution.
