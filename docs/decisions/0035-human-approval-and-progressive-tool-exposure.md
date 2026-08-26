# ADR-0035: Require human approval and progressive tool exposure

- Status: accepted
- Date: 2026-08-26

> Supersession note: ADR-0041 adds mandatory provider-neutral call correlation,
> forbids completed results with calls, and advances conformance to revision 3;
> progressive exposure and human approval semantics are unchanged.

## Context

The public capability grant proves deterministic policy intersection, but it
does not prove that a human reviewed the concrete tools available to one
execution. Giving a provider every approved tool schema on its first turn also
widens prompt context and lets a same-turn response discover and invoke a tool
without a separate parent-controlled boundary.

Real provider adapters, provider selection, and Studio authentication remain
out of scope. This increment must preserve all five public Agent Harness v1
contracts and keep tools, proposals, budgets, and durable records in the parent.

## Decision

World Forge adds a private, instance-scoped
`InMemoryHumanApprovalAuthority`. The host constructs one exact immutable
`ExecutionApprovalReview` for an execution and uses generation/hash compare and
swap to prepare, decide, or revoke it. The review binds the approval and
execution IDs, activation and grant hashes, private-input hash, exact provider
runtime, execution limits, and the ordered eligible `(tool_id,
descriptor_hash)` catalog. An exact decision binds the review hash, asserted
reviewer label, approved or denied outcome, ordered approved subset, expiry,
generation, and its own canonical hash. Expiry is exclusive: a decision is no
longer valid when `now >= expires_at_ms`. Denial and revocation are terminal for
new effects. Exact retries are idempotent; stale hashes or generations fail
closed. Before durable execution begin, the kernel takes one atomic detached
snapshot of the exact prepared review, current decision, generation, hashes,
and state. Every later authorization boundary compares against that snapshot;
a decision arriving during begin is not adopted by the already-fingerprinted
attempt.

`reviewer_id` is only a host-asserted label in this private in-memory slice. It
is not authenticated, durable reviewer evidence. Studio authentication,
durable approval storage, and multi-user policy remain future work.

The capability broker snapshots every registered tool once as the exact
descriptor `{tool_id, required_capability_id, summary, input_schema,
descriptor_hash}`. Summaries and canonical JSON schemas are bounded and closed
over built-in values. Adapters must provide both the exact summary and exact
input schema; the broker invents no fallback metadata. Later adapter or caller
mutation cannot change the catalog, definition, hash, or bound invocation
callable. Eligibility requires
registration, the effective public grant, required-capability compatibility,
and the approved human subset. Missing, hidden, incompatible, denied, expired,
revoked, and unexposed tools share the existing public
`tool_not_authorized` result so the provider receives no authorization oracle.

On the first provider turn, the parent supplies only approved tool ID, bounded
summary, and descriptor hash. The provider may return an ordered unique private
exposure request. If the complete result preflights successfully, the exact
full definition becomes visible on the next turn. A tool is invocable only if
its full definition was exposed at the start of the current turn. Requesting
and calling a tool in the same result, including re-requesting an already
exposed tool, fails whole-batch preflight before any tool or proposal effect.
Full definitions retain first-request order across turns. The worker receives no approval ID, decision,
reviewer, expiry, or authority object.

Cancellation, absolute deadline, and duration checks precede approval checks.
The activation/runtime match also precedes approval. After a provider result,
valid usage and budget accounting occur first, then cancellation/deadline/
duration, then approval, then nested result handling. Cancellation precedes
approval immediately before and after each tool or proposal boundary. The
Linux supervisor polling control includes revocation, so an invalidated
approval can stop a blocked worker; a result is still accepted only after the
existing process-domain-empty proof. Containment uncertainty still escapes
terminalization and leaves the durable prefix for offline
`recovery_required` handling.

The request fingerprint binds the catalog, review, and immutable decision
hashes without changing the SQLite schema. Revocation retains the original
decision hash, so an exact terminal duplicate resolves to existing evidence
before the current approval state is rechecked and performs no new worker or
tool effect. A changed approval or descriptor conflicts. An open or
`recovery_required` execution is never resumed.

Approval in this increment governs only the concrete tool catalog. It does not
approve provider or cloud use, cost, data disclosure, credentials, artifact
truth, Studio memory promotion, or any provider endpoint. The Harness still has
no provider or selection registry.

## Compatibility

All public Agent Harness schemas, catalog rows, generated Studio types, and
canonical fixtures remain byte-identical. Detailed approval state and exposure
errors remain private; contract-facing failures reuse existing bounded codes.
The authenticated private worker transport remains format version 1, while the
fixed conformance runtime advances to revision 2 because its request/result
shape and test-only turn plan changed.

## Proven boundary

Bounded local tests cover exact CAS and concurrency, subset approval, denial,
expiry, revocation, hostile types and aliases, immutable descriptor snapshots,
default deny and non-oracle behavior, next-turn exposure, same-turn escalation,
whole-batch preflight, cancellation/runtime/budget precedence, revocation around
provider/tool/proposal effects, fingerprint conflicts, exact-terminal evidence
after revocation, protocol correlation and schema-hash binding, absence of
approval metadata from workers/public records/SQLite, real two-turn Linux
worker execution, and revocation-driven Linux process-tree cleanup.

## Not proven

This decision adds no authenticated reviewer, durable approval store, Studio
job or UI, real provider/model, provider registry or selection, SDK, endpoint,
credential service, billing proof, external MCP policy, same-UID filesystem or
network sandbox, vendor telemetry enforcement, memory-promotion approval,
Windows worker support, or hosted/native/release evidence. Windows remains
`UNTESTED` and unsupported by the one-shot supervisor.
