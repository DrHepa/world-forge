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
  consume authorization or dispatch. Event payloads bind exact request,
  consumption, attempt, projection, ownership, and rollback hashes. A
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

Before every host call, the controller verifies the complete exact host
projection for the applied/remaining prefix, durably records an exact pending
authorization, atomically claims that pending request, resolves or consumes it
once, durably records consumption, observes the complete precondition again,
and durably marks the attempt dispatching. Only a caller whose relevant
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

### ADR-0050 is one coupled release train, not one oversized commit

The exact implementation-stage matrix is:

| Stage | State | Authority gained |
|---|---|---|
| A — v2 correction-policy foundation | **COMPLETE** | Pure canonical policy validation only |
| B — deterministic controller contracts/store/state machine | **COMPLETE** | Private non-native transaction logic ending at `prepared_unverified` |
| C — concrete closed host interpreter/broker | **ABSENT** | None; the binding says `native_implementation_state: absent` |
| D — Studio Director domain, Store, protocol, and UI v7 | **ABSENT** | None |
| E — separately authorized host preparation | **ABSENT** | None |
| F — native observed evidence and bounded real inference | **ABSENT** | None |

The overall ADR-0050 implementation therefore remains **PARTIAL**,
`availability: unavailable`, and `production_eligible: false`.

The later Studio authority must bind an authenticated Director decision to an
exact controller plan without putting Ollama into the Harness catalog. Host
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
