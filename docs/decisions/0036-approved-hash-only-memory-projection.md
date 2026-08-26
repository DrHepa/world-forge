# ADR-0036: Record separately approved hash-only memory projections

- Status: accepted
- Date: 2026-08-26

## Context

The public `AgentMemoryProjection` v1 contract already describes an immutable,
identity-only projection, but the private Harness had no authority that could
approve candidates, no deterministic compiler for that document, and no
durable way to append its reserved `memory.projected` event. Tool approval is
not memory approval. Provider output also cannot choose retention, truth,
scope, privacy, or promotion policy.

This increment must not persist raw candidate values, infer semantic summaries,
change any public Harness byte, or weaken the existing event-log crash and
recovery boundary.

## Decision

World Forge adds an ephemeral, instance-scoped
`InMemoryMemoryProposalSource`. A host explicitly supplies one execution ID,
one public projection kind, one portable subject ID, and one exact bounded JSON
value. The source validates and copies the value, gives it a code-owned hash
identity, and returns only detached identity records. Exact candidates
deduplicate; different values remain distinct until review. At most 64
candidates and bounded canonical bytes may exist for one execution. Raw values
never enter representations, errors, fingerprints, approval records, public
records, or durable storage.

Memory review uses a separate `InMemoryMemoryApprovalAuthority`. Its immutable
review binds the succeeded receipt, exact ordered pre-projection event chain and
head, complete candidate snapshot, and the fixed
`lossless_hash_projection` policy. Generation/hash compare-and-swap governs
prepare, ordered-subset approve, deny, expiry, and revoke. The reviewer ID is an
asserted label, not an authenticated identity. Execution/tool approval objects
cannot satisfy this authority.

The provider-free compiler is lossless with respect to approved candidate
identities: it rehashes the exact raw values, deduplicates only identical
`(kind, subject_id, value_hash)` triples, rejects multiple approved value hashes
for one `(kind, subject_id)`, and sorts code-owned public IDs by UTF-8 bytes. It
does not summarize, merge, rank, infer truth, or call a provider. Every entry
references the complete exact terminal event lineage supplied by the parent.

`MemoryProjectionCoordinator.prepare_review` accepts only an exact terminal
`succeeded` execution. `project` revalidates the exact terminal lineage,
candidate snapshot, immutable approval snapshot, decision, fixed policy, and
request fingerprint. Approval and candidate locks remain held across the final
atomic record boundary, so concurrent revoke or proposal mutation cannot race a
new projection. An exact already-recorded request returns existing evidence;
any changed review, decision, candidate snapshot, policy, receipt, event head,
execution fingerprint, projection, or event conflicts. The coordinator never
runs a provider, worker, tool, artifact proposal, or memory proposal.

The private `AgentEventLog` schema advances to version 2 with one closed
`memory_projections` table keyed by execution and unique projection ID/hash. A
privileged atomic operation inserts the canonical projection, appends exactly
one `memory.projected` event after the succeeded receipt, and advances the
existing sequence/generation/head state. The receipt remains the terminal
execution outcome. Direct `append_event` cannot inject a projection. Replay
validates the complete visible/internal schema, bounded physical integrity and
foreign-key results, lifecycle, public aggregate lineage, relational columns,
projection bytes, event chain, and state hash. Retrying the exact original
finalization after that one projection is evidence-only and idempotent.

An exact version-1 ordinary store is verified and transactionally migrated to
version 2 by adding only the new table and changing `schema_version`; existing
execution state hashes retain their version-1 document format. Offline recovery
accepts exact version 1 or 2 without creating or migrating the store. It serves
reads from a digest-bound query-only image materialized entirely offline from
retained main and strictly validated committed WAL bytes, preserving the
original main/WAL/SHM evidence until an explicit recovery mutation revalidates
and opens it. Recovery rejects any rollback-journal sidecar until a separately
reviewed parser exists. Ambiguous projection faults, including private domain exceptions,
are accepted only when replay proves the
exact projection bytes, event bytes, fingerprint, and state transition;
otherwise the operation is `event_log_projection_indeterminate`.

## Compatibility

All five public Agent Harness v1 schemas, catalog rows, generated Studio types,
and canonical fixtures remain byte-identical. `ProviderTurnRequest`, the worker
protocol, runtime revision, provider contracts, and receipt
`replay_support: not_claimed` are unchanged. The only durable migration is the
private SQLite schema from exact version 1 to version 2.

## Proven boundary

Bounded local tests cover hostile candidate values and aliases, depth/byte/count
bounds, copy isolation, deterministic insertion order, exact deduplication and
value conflicts, separate approval CAS/concurrency/deny/expiry/revoke/stale
behavior, terminal-state gating, exact lineage, atomic and concurrent record,
fault reconciliation, exact finalization retry, exact v1 migration,
byte-preserving v1/v2 crash-WAL recovery reads, fail-closed rollback-journal
rejection, physical index
corruption, schema/projection/event/state tamper, direct injection rejection,
and absence of raw sentinels from exception graphs, public evidence, and SQLite
main/WAL/journal bytes. Existing hostile crash-WAL and rollback-journal rejection
tests remain authoritative.

## Not proven

This increment adds no semantic summarizer, provider/model/SDK, vector store,
embedding, memory hydration, global or project scope, truth promotion, retention,
deletion, tombstone, authenticated reviewer, durable raw content, Studio job or
UI, Tool Center behavior, external MCP policy, or hosted/native/release claim.
Those authorities remain future Studio work.
