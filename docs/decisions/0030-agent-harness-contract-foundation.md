# ADR-0030: Add immutable Agent Harness activation and grant contracts

- Status: accepted
- Date: 2026-08-23

## Decision

World Forge publishes four closed, hash-bound v1 documents. Slice 1B.1 publishes
`AgentWorkerActivation` and `AgentCapabilityGrant`; Slice 1B.2 publishes
`AgentEvent` and `AgentExecutionReceipt`. They bind immutable role, work-order,
runtime, prompt, input, event-subject, invocation, result, outcome, and usage
identities as applicable. `MemoryProjection` remains pending. Activations are
always `fresh` context. A grant's effective capabilities and tools are the exact
sorted unique intersection of policy, role and work-order sets; activation
requests repeat the work-order sets exactly.

## Boundary

These validators prove document structure and lineage only. They do not prove
worker execution, isolation, authority, replay, tool invocation, or evidence
quality. The documents intentionally contain no prompts, transcripts, secrets,
credentials, endpoints, commands, environment, filesystem paths, stderr, or
free-form errors.

The standard JSON Schema shape remains closed. The canonical Studio generator
also applies its named `x-world-forge-agent-harness-coherent` AJV keyword for
canonical hashing, ordered-set, requested/work-order, grant-intersection,
event-subject, receipt-outcome, and usage semantics; structural JSON Schema
alone does not prove all cross-field or aggregate-lineage invariants.

## Slice 1B.2 addition

`AgentEvent` and `AgentExecutionReceipt` add hash-bound event-log lineage and
identity-only audit receipts. They do not prove that an execution occurred;
`MemoryProjection` remains pending.
