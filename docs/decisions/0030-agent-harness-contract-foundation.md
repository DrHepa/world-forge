# ADR-0030: Add immutable Agent Harness activation and grant contracts

- Status: accepted
- Date: 2026-08-23

## Decision

World Forge publishes two closed, hash-bound v1 documents: `AgentWorkerActivation`
and `AgentCapabilityGrant`. They bind immutable role, work-order, runtime,
prompt and input identities. Activations are always `fresh` context. A grant's
effective capabilities and tools are the exact sorted unique intersection of
policy, role and work-order sets; activation requests repeat the work-order
sets exactly.

## Boundary

These validators prove document structure and lineage only. They do not prove
worker execution, isolation, authority, replay, tool invocation, or evidence
quality. The documents intentionally contain no prompts, transcripts, secrets,
credentials, endpoints, commands, environment, filesystem paths, stderr, or
free-form errors.

The standard JSON Schema shape remains closed. The canonical Studio generator
also applies its named `x-world-forge-agent-harness-coherent` AJV keyword for
canonical hashing, ordered-set, requested/work-order, and grant-intersection
semantics; structural JSON Schema alone does not prove those cross-field
invariants.
