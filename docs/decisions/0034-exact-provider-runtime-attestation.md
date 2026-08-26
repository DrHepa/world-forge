# ADR-0034: Attest the exact injected provider runtime

- Status: accepted
- Date: 2026-08-26

## Context

ADR-0031 lets the host inject one private `ProviderAdapter`, and ADR-0033 moves
the fixed conformance adapter behind a killable Linux process boundary. The
kernel did not yet prove that the injected adapter identity matched the exact
runtime requested by `AgentWorkerActivation`. A receipt could therefore repeat
the activation binding without checking the adapter that produced the turn.

The existing public activation and receipt contracts already define the needed
closed binding: portable `id`, positive JavaScript-safe `revision`, and lowercase
SHA-256 `content_hash`. No provider registry or new public contract is needed.

## Decision

Every private `ProviderAdapter` exposes one `runtime_binding` document with the
exact existing binding fields. `AgentExecutionKernel` reads and strictly
snapshots it once during construction. The document must be a built-in `dict`
with exactly built-in scalar values; mapping and scalar subclasses, missing or
unknown fields, booleans as revisions, non-portable IDs, and malformed hashes
raise `provider_runtime_binding_invalid`. This happens before a durable begin,
broker activation, provider turn, worker spawn, tool invocation, or proposal.
After validating that binding, the kernel reads the adapter's bound `turn`
callable exactly once and stores the adapter, callable, and binding in one frozen
private authority. Ordinary assignment to `provider` or `_provider`, replacement
or deletion of that private authority, and later mutation of an adapter endpoint
selector cannot redirect execution or skip validation of a replacement binding.
This is an ordinary same-process API boundary; it deliberately does not claim to
resist `object.__setattr__`, malicious private/module reflection, memory
corruption, or a hostile embedding application.

After an exact request has durably begun, cancellation and absolute-deadline
checks retain their existing precedence. If neither applies and the frozen
adapter binding differs from `activation.runtime`, the kernel performs no
broker, provider, worker, tool, or proposal action and atomically records the
existing contract-valid `failed` receipt with `provider_failed`. No new public
failure vocabulary is introduced. A matching binding continues through the
normal execution path, so the receipt's required `runtime_binding` is exactly
the activation binding that the injected adapter attested.

An exact terminal duplicate still reaches the durable coordinator's existing
evidence-only path. It performs no new binding read and no provider or worker
action. The host remains the sole selection authority: the Harness contains no
provider registry, provider name selector, SDK, endpoint, credentials, or
network policy.

The conformance supervisor exposes the same fixed identity already authenticated
inside its request and response frames. Its private runtime ID becomes
`worldforge_conformance_provider` because public Harness binding IDs are
portable lowercase identifiers and do not permit dots. Its content hash remains
derived from the exact bootstrap template. The bootstrap and registry consume
the same private immutable scalar values. A frozen slots binding is closed over
by a no-argument identity factory, and every exposed identity document is a
fresh built-in `dict`; mutating one cannot select a later runtime.

## Compatibility

All five public Agent Harness schemas, catalog entries, generated Studio types,
and canonical fixtures remain byte-identical. The runtime-ID correction affects
only the private conformance protocol and local integration evidence. Existing
fixture files retain their neutral `harness_runtime` identity; tests clone them
in memory and bind the real conformance identity without changing fixture bytes.

## Proven boundary

Bounded local tests cover exact binding validation before authority, hostile
mapping and scalar inputs, immutable snapshotting of the binding and turn
callable, ordinary authority-replacement attempts, mutable endpoint selectors,
mismatch failure without broker or adapter effects, cancellation/deadline
precedence, matching execution, receipt binding, exact-terminal duplicate
zero-side-effect behavior, and the bootstrap-derived supervisor identity.

## Not proven

This decision does not add provider discovery, provider selection, a real
provider/model, SDKs, credentials, endpoints, billing verification, network or
same-UID isolation, telemetry enforcement, Studio control-plane state, Windows
worker support, deterministic provider replay, or hosted/native/release
evidence.
