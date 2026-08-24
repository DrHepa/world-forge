# ADR-0026: Define a World Forge-owned provider-neutral Agent Harness

- Status: accepted as planned Slice 1 foundation
- Date: 2026-08-23

## Context

World Forge needs a future authoring-time agent execution boundary without
turning a provider, a model, an agent transcript, or an external harness into a
source of project authority. Existing Studio boundaries already keep reviewed
source, canon, assets, and releases under explicit human governance.

## Decision

World Forge will own a provider-neutral Agent Harness. Its planned vocabulary
includes an agent execution kernel, append-only `AgentEventLog` with replay,
provider adapters, isolated and killable worker activation/lifecycle,
capability grants, execution receipts, and memory projections. A worker starts
with a task-specific fresh context and only the capability intersection granted
by global policy, role, and work order.

The event log is the execution record. A `MemoryProjection` is approved,
derived data, never a complete raw conversation or an alternate source of
project truth. Receipts record the model/configuration, prompts or approved
prompt identities, tools, hashes, costs, and result identities needed to
explain or replay an execution within its declared limits.

Studio alone owns project, canon, assets, and release authority. The Harness
cannot self-approve, apply source changes, promote assets, or release a game.
DeepSeek Harness may inform design as a reference only; it is neither a
runtime dependency nor a fork. `codebase-memory-mcp` remains an optional,
development-only, read-only, non-authoritative benchmark with an external
index/cache. It is not a product dependency, source authority, runtime input,
or replacement for direct reads, tests, runtime evidence, Engram decisions, or
ADRs. Adoption requires all measured gates: at least 30% net-token reduction
across the full representative task set; at least 50% token reduction for
structural-navigation tasks; no more than a two-percentage-point quality loss; zero critical
omissions; incremental p95 latency of at most five seconds; zero tracked
changes; and zero unauthorized egress.

This ADR defines no executable provider adapter, event store, worker, Studio
protocol, or UI. Slice 2B retains the closed recorded-result plan, observation,
and report schemas for the optional codebase-memory benchmark and adds only a
pure deterministic evaluator plus an explicit-input atomic no-replace CLI.
Those surfaces evaluate supplied evidence only: they do not run a benchmark,
contact the candidate, inspect the checkout, or independently authorize
adoption. The committed evidence is synthetic and `not_evaluable`; no actual
A/B/C benchmark has been run and no candidate has been adopted.

## Consequences

- Provider integrations can be introduced behind one Forge-owned lifecycle and
  receipt model without granting them project authority.
- Replay and recovery can be designed from durable events rather than raw chat
  retention.
- Any memory benchmark remains development-only, read-only, and
  non-authoritative, and must satisfy every adoption gate without changing
  tracked files or authorized checkout boundaries.
- Runtime remains free of AI/model inference and provider dependencies.

## Rejected alternatives

### Adopt DeepSeek Harness as the product harness

Rejected because a reference implementation cannot define World Forge's
project-authority, compatibility, and evidence boundaries.

### Treat agent memory as canonical project knowledge

Rejected because reviewed source, tests, runtime evidence, and accepted ADRs
must remain independently inspectable authorities.
