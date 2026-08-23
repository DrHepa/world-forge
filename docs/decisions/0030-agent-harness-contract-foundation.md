# ADR-0030: Add immutable Agent Harness lineage contracts

- Status: accepted
- Date: 2026-08-23

## Decision

World Forge publishes five closed, hash-bound v1 documents. Slice 1B.1 publishes
`AgentWorkerActivation` and `AgentCapabilityGrant`; Slice 1B.2 publishes
`AgentEvent` and `AgentExecutionReceipt`; Slice 1B.3 publishes
`AgentMemoryProjection`. They bind immutable role, work-order, runtime, prompt,
input, event-subject, invocation, result, outcome, usage, approved-review, and
hash-only projection identities as applicable. Activations are always `fresh`
context. A grant's effective capabilities and tools are the exact sorted unique
intersection of policy, role and work-order sets; activation requests repeat the
work-order sets exactly.

## Boundary

These validators prove document structure and lineage only. They do not prove
worker execution, isolation, authority, replay, tool invocation, or evidence
quality or memory truth. The documents intentionally contain no prompts,
transcripts, memory text, free-form rationale or errors, secrets, credentials,
tokens, provider payloads, endpoints, commands, environment, filesystem paths,
stderr, or executable content.

The standard JSON Schema shape remains closed. The canonical Studio generator
also applies its named `x-world-forge-agent-harness-coherent` AJV keyword for
canonical hashing, ordered-set, requested/work-order, grant-intersection,
event-subject, receipt-outcome, usage, approved-review, projection-source, and
entry-subset semantics; structural JSON Schema alone does not prove all
cross-field or aggregate-lineage invariants.

## Slice 1B.2 addition

`AgentEvent` and `AgentExecutionReceipt` add hash-bound event-log lineage and
identity-only audit receipts. They do not prove that an execution occurred;
the original memory-projection event format remained reserved at this slice.

## Slice 1B.3 addition

`AgentMemoryProjection` adds an approved identity-only projection bound to one
exact receipt and one or more exact supplied events. Its entries contain only
typed identities and hashes. It does not mutate Engram, infer memory truth,
prove execution or replay, or require `memory.propose` in the existing grant;
review authority is represented independently by the closed approved review.
