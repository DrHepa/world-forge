# ADR-0037: Govern exact provider execution before real adapters

- Status: accepted
- Date: 2026-08-26

> Supersession note: ADR-0038 replaces this decision's one-entry executable
> catalog with exactly two code-owned, network-free, non-production entries;
> all selection, approval, fingerprint, revocation, and zero-secret rules here
> remain authoritative.

## Context

ADR-0034 attests the injected adapter's exact activation-runtime triple, while
ADR-0035 governs concrete tool exposure. Neither decision authorizes provider
or model selection, local or cloud deployment, a destination, disclosed data,
credentials, telemetry, pricing, or spend. Adding a vendor SDK or generalizing
the fixed worker registry before those authorities existed would turn an
identity check into an unsafe provider-selection mechanism.

The existing five public Agent Harness v1 contracts have no place for private
provider policy and must remain byte-compatible. Provider governance therefore
belongs to the host-side Harness boundary, not to public receipts, generated
games, or `src/isoworld`.

## Decision

World Forge adds one code-owned runtime catalog. An immutable
`ProviderRuntimeSpec` binds the exact runtime triple, provider/model/version,
deployment and network classes, endpoint policy, enforced egress evidence,
telemetry attestation, pricing identity, credential requirement, supported
platform, production eligibility, and a canonical content hash. A
`ProviderRuntimeCatalog` resolves only the exact triple and specification hash.
No execution request can supply a command, module, path, factory, SDK, URL, or
environment. As superseded by ADR-0038, the closed catalog has exactly the
conformance runtime and deterministic offline probe; both are Linux-only,
network-free, and explicitly `production_eligible: false`.
Valid loopback and Internet descriptors can be validated as data, but this
catalog rejects them as unavailable because no enforced network runtime exists.

Cross-field validation is closed. `none` has no endpoint, egress, telemetry,
pricing, or credential authority. `loopback` requires a canonical numeric
`127.0.0.1` or `::1` origin with an explicit port, no userinfo, wildcard,
redirect, path, query, or fragment, plus exact enforcement evidence. `internet`
requires a cloud HTTPS origin, allowlist-policy identity, redirects disabled,
egress and telemetry evidence, credential requirements, exact pricing and
currency, and a non-null execution cost ceiling. Declaration alone does not
make a networked runtime executable.

One immutable `ProviderExecutionSelection` binds the catalog and spec hashes,
exact non-secret configuration hash, disclosure-plan hash and data classes,
exact base-payload hash, tool-catalog hash, execution limits, pricing identity,
and an opaque random credential-revision identity. Secret bytes and hashes of
secret bytes are not valid credential-revision identities.

Provider approval is separate from tool and memory approval. A
`ProviderGovernanceReview` binds the execution, activation, grant, WorkOrder,
private input, and four independently bound review facets:

1. exact provider/model/runtime/configuration selection;
2. destination, endpoint, egress, redirect, and telemetry evidence;
3. disclosed data classes, disclosure plan, and exact base payload;
4. pricing, currency, token limit, and maximum authorized cost.

An approved or denied `ProviderGovernanceDecision` echoes the approval,
execution, activation, grant, WorkOrder, and private-input bindings, every facet
hash, review hash, asserted reviewer label, expiry, generation, and canonical hash.
`InMemoryProviderGovernanceAuthority` applies generation/hash compare-and-swap
to prepare, decide, revoke, snapshot, and check. Expiry is exclusive. The
reviewer label is asserted rather than authenticated, and this in-memory state
is not a Studio durability claim.

The kernel accepts only the exact code-owned catalog, freezes its
resolution and one detached authority snapshot before durable begin. Its
private request fingerprint always binds supplied approval identifiers, the
canonical selection hash, explicit catalog and authority presence, and any
resolved spec, configuration, review, and immutable decision hashes. Missing
authority cannot make distinct supplied controls appear to be an exact retry.
A decision arriving during `begin_execution` is not adopted. An exact terminal
duplicate is resolved by durable evidence before live revocation is checked, so
it has no new provider, worker, broker, credential, tool, proposal, or network
effect.

For a new attempt, cancellation, deadline, and duration checks precede runtime
matching; runtime matching precedes provider approval; provider approval
precedes tool approval and broker authority. Missing, denied, expired, revoked,
or stale provider authority collapses to the existing public
`provider_failed` code. Detailed governance causes remain private. During a
turn the parent polls provider revocation and can stop a blocked Linux worker;
an authenticated result is accepted only after the existing process-domain
empty proof. Valid returned usage is accounted before a post-provider
revocation check. Containment uncertainty still leaves the durable prefix open
for exclusive offline `recovery_required` handling and writes no receipt.

Credential bytes remain owned by a future Studio vault. They are not accepted
by the catalog, selection, kernel, worker protocol, arguments, environment,
errors, public records, or SQLite event log. This decision creates no credential
lease or injection mechanism.

## Compatibility

All five public Agent Harness v1 schemas, contract-catalog rows, generated
Studio types, and canonical fixtures remain byte-identical. Private EventLog v2,
the worker protocol, and the fixed conformance runtime revision remain
unchanged; ADR-0038 adds only its separately identified offline probe.
`src/isoworld` remains provider-free. No GitHub Actions workflow is added.

## Proven boundary

Bounded local tests cover exact built-in types and hashes, duplicate and
mutation rejection, endpoint and network cross-fields, catalog copy isolation,
selection drift, four-facet decision echo, CAS concurrency, denial, exclusive
expiry, revocation, stale state, detached snapshots, missing-authority zero
provider effects, decision-during-begin isolation, fingerprint drift, exact
terminal duplicate evidence after revocation, cancellation precedence,
credential-metadata privacy, and Linux blocked-worker revocation cleanup.
Runtime, contract, identity, and public-byte audits remain separate handoff
gates.

## Not proven

No real provider, model, SDK, network call, endpoint enforcement, credential
vault, one-use credential lease, billing reconciliation, authenticated or
durable Studio reviewer, generalized adapter factory, deterministic provider
replay, same-UID filesystem/network sandbox, or vendor telemetry enforcement is
implemented. The only executable runtimes are the two non-production
code-owned workers defined by ADR-0038. Windows remains unsupported and
`UNTESTED`; hosted, native release, and production readiness are not claimed.
