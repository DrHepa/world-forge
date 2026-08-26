# ADR-0031: Add a provider-free Agent Execution Kernel foundation

- Status: accepted
- Date: 2026-08-24

ADR-0032 later adds the private durable journal boundary and supersedes only
the failed-journal follow-up rule: any begin, append, or finalization exception
is treated as ambiguous and causes no further journal write.

> Supersession note: ADR-0041 replaces arbitrary provider history with an exact
> private correlated transcript and preserves this kernel's public records.

## Context

ADR-0030 publishes five immutable Agent Harness lineage contracts but does not
execute them. The next bounded step needs to prove that trusted activation and
grant documents can drive a deterministic lifecycle without introducing a
provider SDK, process worker, durable Studio job, or new public contract.

## Decision

World Forge adds an internal, synchronous Agent Execution Kernel under
`src/worldforge/agent_harness/`. It validates the existing activation and grant
before use. Before consulting the clock or activating the broker, it requires
exact built-in request identifiers, limit scalars, activation/grant JSON
containers and scalars, then copies them into code-owned records. It starts
every execution with empty provider history, derives authority only from the
grant's effective sets, and routes tools and proposal ports through a
default-deny capability broker. Clock values must be exact bounded integers and
broker activation identifiers must be exact portable strings. Provider and
tool adapters cannot select execution, event, invocation, receipt, or artifact
identities. Private inputs, outputs, tool arguments, and proposal payloads
exist only on internal ports and never enter public events or receipts.

The kernel records `worker.activated`, `grant.issued`, `execution.started`, an
optional `execution.cancel_requested`, and then atomically records the receipt
with `execution.receipt_recorded`. The journal owns compare-and-append sequence
and hash-head checks. Cancellation visible before an append, after a successful
append, or after a failed append on a still-usable journal suppresses later
normal lifecycle events and records the canonical cancellation event and
receipt. The receipt always states `replay_support: not_claimed`. Tool request
evidence is SHA-256 only. An unknown, unauthorized, or requested-but-ineffective
tool attempt is a receipt-level `tool_not_authorized` failure and is not
misrepresented as an invocation. `memory.propose` may return a closed identity
to the caller boundary, but this kernel neither builds an
`AgentMemoryProjection` nor emits `memory.projected`.

Provider-returned usage is type- and bounds-validated and accounted immediately
after the provider returns, before nested result validation or cancellation.
Valid over-budget usage remains visible in the failed receipt; invalid usage is
not trusted. Usage invalidity or a token/cost breach takes deterministic
precedence over a malformed nested result and cancellation discovered at that
returned boundary. Once usage is valid and within budget, cancellation is
checked before nested result validation, so cancellation wins over a malformed
nested collection returned by the same provider boundary. The remaining result
is then converted into code-owned JSON snapshots and preflighted as one batch
before a tool or proposal port can run. Only exact internal
result/usage/call/proposal types and tuple collections are accepted. Tool calls
are bounded by the remaining execution limit and 128; artifact and memory
proposals are each bounded to 64 across one execution. Private fields and
cumulative provider history are bounded to 64 KiB each.

Turn, tool-call, token, cost, and duration checks are cooperative. Count,
token, cost, and duration maxima are inclusive: equality is allowed and the
first greater value fails. An absolute deadline is exclusive: a boundary at or
after the deadline is cancelled. Cancellation and deadline checks run before
activation side effects; around journal, provider, tool, and proposal
boundaries, including paths where a boundary raises an ordinary exception;
immediately around proposal side effects; and immediately before atomic
finalization. Cancellation or a deadline detected after a
provider/tool/proposal failure takes precedence over that boundary failure.
Provider usage validation/accounting retains the precedence described above.

These checks cannot interrupt a blocked adapter or roll back a tool/proposal
that completed before cancellation became visible. An ambiguous side effect is
never retried. For an otherwise successful execution, cancellation first
observed during an atomic finalizer that raises, or after a finalizer returns,
yields bounded `journal_finalization_ambiguous` rather than a false successful
return; this foundation cannot safely synthesize a replacement receipt without
a durable recovery contract.

Provider, tool, artifact-proposal, and memory-proposal ordinary exceptions are
mapped to fixed kernel-owned reason codes without adapter strings or causes.
Tool descriptor strings are captured once during broker construction, and
untrusted identity mappings cannot inject a `BrokerError` reason. `BaseException`
control signals deliberately propagate after broker/kernel cleanup and do not
become receipts. Journal calls receive deep-copied records that are exactly
validated and canonically serialized before the call, then revalidated and
compared by code-owned bytes afterward. Mutation detection does not invoke
equality supplied by journal objects. Argument mutation, final aggregate
invalidity, or an atomic failure raises a bounded kernel error. Late journal
mutation cannot change the returned records. This does not prove that an
arbitrary durable journal persisted the same bytes.

This slice supplies only deterministic in-memory fakes in tests. Durable
persistence, scheduling, recovery, and process ownership remain deferred to
the Studio control plane.

## Proven boundary

Deterministic fake-only tests prove canonical event/receipt construction,
ordered hash chaining, aggregate validation, fresh per-execution history,
grant-derived default-deny routing, sealed turn snapshots, whole-batch
preflight, bounded accounting, cooperative cancellation/deadlines at the
enumerated synchronous boundaries, compare-and-append rejection,
atomic-finalization failure/mutation detection, same-kernel and shared-broker
activation conflict rejection, exact top-level input/clock containment,
overloaded-equality-resistant journal mutation detection, fixed public failure
codes, and absence of the tested private values from public records.

## Not proven

This foundation does **not** prove any real provider or model, provider billing
or usage accuracy, durable recovery, isolation or hard kill, external MCP
safety, memory approval or projection, artifact promotion, Studio jobs/UI/Team
Mode, deterministic provider replay, or hosted/native/release evidence.
Provider-reported usage is budget input, not billing proof.

## Consequences

- Provider integrations can target small internal ports without becoming
  project authority or changing the five public Harness contracts.
- Studio can later own durable execution and recovery without treating this
  in-process kernel as a worker or persistence implementation.
- Cooperative cancellation is honest but cannot stop a blocked adapter; hard
  termination requires a future isolated worker boundary.
