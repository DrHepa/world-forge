# ADR-0038: Dispatch only closed code-owned provider runtimes

- Status: accepted
- Date: 2026-08-26

> Supersession note: ADR-0040 advances the deterministic probe to revision 3
> and permits its exact governed loopback variant through a parent-owned
> gateway; the conformance runtime and closed two-ID registry remain unchanged.
>
> ADR-0041 advances conformance to revision 3, the deterministic probe to
> revision 4, and the private provider-turn protocol to version 2 while
> retaining both runtime IDs and exactly two registry entries.
>
> ADR-0042 advances conformance to revision 4, the deterministic probe to
> revision 5, and the private provider-turn protocol to version 3 with explicit
> code-owned usage-policy identities; the closed two-runtime catalog remains.

## Context

ADR-0033 proved one killable Linux worker around a fixed conformance runtime,
and ADR-0037 added provider selection and approval while deliberately keeping
that conformance runtime as the sole executable catalog entry. Before adding a
real adapter, the Harness needs evidence that an exact governed selection can
choose between more than one runtime without turning the worker boundary into a
command, module, path, factory, environment, or endpoint injection surface.

## Decision

World Forge replaces the one-row executable catalog with exactly two private,
code-owned, Linux-only, network-free, non-production entries:

1. `worldforge_conformance_provider`, revision 2; and
2. `worldforge_deterministic_probe_provider`, revision 1.

The first entry retains its exact bootstrap-template bytes and SHA-256 identity.
The second is an offline deterministic probe written only with fixed standard
library code. It hashes the supplied private input and history and reports
bounded counts and correlation fields. It has no provider SDK, endpoint,
credential, file operation, or network operation and cannot request tools or
propose artifacts or memory.

A private enum is the only registry selector. Each frozen table entry binds that
enum member, one validated immutable worker artifact, exact runtime ID and
revision, private protocol version, bootstrap template and final source,
template-derived hash, exact `ProviderRuntimeSpec`, and a closed environment
profile. Each code-owned no-argument factory is invoked exactly once while the
registry is constructed; its callable is not retained in the entry or consulted
again. Registry access revalidates the stored artifact against the canonical
construction snapshot, hash-token cardinality, final embedded hash, exact
specification equality, unique runtime/spec identities, and catalog order, then
returns detached values. A rebound module factory, alternating later factory
result, mutated returned value, stale one-row catalog, forged selection,
unknown runtime, networked descriptor, or production-eligible descriptor cannot
select a worker.

`code_owned_provider_catalog()` returns the complete two-entry detached catalog.
The historical private `fixed_provider_catalog()` name remains only as an alias
to that complete catalog; `fixed_runtime_identity()` and
`fixed_runtime_spec()` continue to identify the default conformance runtime.
This supersedes ADR-0037's one-entry catalog statement without weakening its
provider-governance requirements.

`OneShotProviderSupervisor()` remains the conformance default.
`OneShotProviderSupervisor.for_selection(...)` resolves an exact
`ProviderExecutionSelection` through the code-owned catalog and chooses the
matching entry. At construction it captures the validated entry, detached
specification, protocol binding, complete worker command and environment, Linux
process supervisor, and dispatch callable as one frozen authority. Ordinary
public or private attribute assignment/deletion, later selector mutation, and
later registry/factory rebinding cannot retarget that captured callable. The
spawned broker receives the captured launch authority rather than resolving a
mutable registry selector at execution time, and launches the already captured
absolute Python executable with exactly
`-I -B -S -u -X utf8 -c <code-owned source>`, `shell=False`, and no inherited
host environment. No request can provide a command, callable, source, module,
path, URL, argument, or environment value.

The supervisor's authenticated request/result path uses that same captured
runtime authority while preserving the existing private on-wire version 1
document shape, field names, framing, bounds, and HMAC construction. Runtime
identity is inside each authenticated frame. A frame built for one entry fails
validation under the other entry even with the same per-spawn key and
correlation values. The selected worker independently accepts only its own exact
triple.

This is normal in-process authority hardening. It does not claim protection
against explicit `object.__setattr__` bypass, malicious private/module
reflection before authority construction, or memory corruption in a hostile
host.

The kernel accepts only the exact two-entry catalog and retains ADR-0037's
selection, approval, fingerprint, revocation, budget, and containment order.
The selection must match both the injected supervisor identity and exact
catalog specification. A decision or selection prepared against the former
one-entry catalog fails closed. Exact terminal duplicates still return durable
evidence before any new worker or live-governance effect.

## Compatibility

The five public Agent Harness v1 schemas, contract-catalog rows, generated
Studio types, canonical fixtures, private worker on-wire version 1, EventLog
schema, and `src/isoworld` remain unchanged. No GitHub Actions workflow is
added. The conformance bootstrap template remains byte-identical and keeps the
same runtime content hash.

## Proven boundary

Bounded local Linux tests pin the original conformance bytes/hash, validate two
distinct immutable entries and detached catalogs, prove one factory call per
constructed entry, reject artifact/table/hash/spec tampering, reject
cross-runtime authenticated frames, and prove exact probe selection plus
process-domain-empty release. Adversarial tests mutate the original selection,
rebind the registry/factory, and attempt ordinary public/private authority
replacement after supervisor construction; the captured probe protocol,
artifact, process launch, result, and receipt identity remain aligned. Exact
provider governance and evidence-only terminal duplicate behavior remain green,
and stale, unknown, networked, and production-labeled choices produce zero
worker spawns.

## Not proven

No real provider, model, SDK, endpoint, credential lease, network call, billing
reconciliation, vendor telemetry enforcement, same-UID filesystem isolation,
or network sandbox is implemented. The fixed sources contain no network logic;
that is deliberately no network-isolation claim. Windows remains unsupported
and `UNTESTED`. Studio durability/authentication, hosted/native release
evidence, and production readiness are also not proven.
