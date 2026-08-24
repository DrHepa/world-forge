# ADR-0032: Add a private durable Agent Event Log

- Status: accepted
- Date: 2026-08-24

## Context

ADR-0031 deliberately leaves persistence and recovery outside the provider-free
Agent Execution Kernel. A durable boundary is needed before any provider or
Studio integration can claim that an exact execution identity was recorded,
that an event prefix survived a crash, or that a terminal receipt and its final
event were committed together. That boundary must not widen the five published
Agent Harness v1 contracts or turn an interrupted external side effect into an
exactly-once claim.

## Decision

World Forge adds a dedicated, host-supplied `AgentEventLog` under
`src/worldforge/agent_harness/`. It is a private SQLite format at version 1 and
is not part of `StudioStore`. The host supplies a dedicated storage root; the
kernel receives the store only through its internal `ExecutionJournal` port.
The store uses WAL, `synchronous=FULL`, foreign keys, and `BEGIN IMMEDIATE` for
every transaction. Activation, grant, event, and receipt documents are stored
as canonical UTF-8 JSON BLOBs. An execution is bounded to five events and 8 MiB
of stored documents, and open-row pagination is bounded to 100 rows. Private v1
uses centralized canonical DDL and compares every `sqlite_schema` row with
non-null SQL against the exact expected manifest, including names beginning
with `sqlite_`. SQLite-created autoindexes have null SQL and are naturally
excluded; any other internal-looking object fails closed. The store also checks
columns, unique indexes, and foreign-key shapes. Startup checks at most the
first `PRAGMA foreign_key_check` violation inside `BEGIN IMMEDIATE` and fails
closed if one exists or the check errors.

`begin_execution` atomically binds one execution ID and log ID to the exact
canonical activation and grant bytes plus a request fingerprint. The
fingerprint contains only versioned, code-owned controls and hashes: exact
request identifiers and limits, activation and grant content hashes, and a
SHA-256 digest of an already sealed valid private-input snapshot. It never
stores the private input. If private input cannot be sealed through exact
built-in JSON types, the fingerprint is null rather than fabricated. That first
execution may durably record its bounded failure receipt, but a null identity is
never duplicate evidence: every retry conflicts at begin and performs no
provider call. A terminal execution with a non-null matching fingerprint and
exact documents is duplicate evidence; only the private coordinator may return
that existing evidence without running the kernel again. A direct kernel call
never re-executes it. Any differing duplicate conflicts before broker
activation.

`append_event` verifies the exact expected generation, next sequence, previous
hash, lifecycle state, public aggregate, and bounded size in one transaction.
It inserts an append-only event row and advances the execution head, count, and
generation atomically. `finalize` atomically inserts the append-only receipt and
terminal `execution.receipt_recorded` event, then advances state, head, count,
receipt anchor, and generation. An exact duplicate finalization is idempotent;
a differing duplicate conflicts. After an ordinary exception at a commit
boundary, a fresh transactional reread must prove the exact immediate committed
state and projection. Append reconciliation accepts only an open row whose
generation and sequence advanced by exactly one and whose exact submitted bytes
and content hash are the new tail. A later open, terminal, or
`recovery_required` state is indeterminate and poisons the live writer.

Replay revalidates every stored public document, canonical byte encoding,
content hash, relational ID/hash projection, private state hash, event chain,
aggregate lineage, size bound, and lifecycle fold. It returns frozen,
code-owned strings, integers, bytes, and byte tuples only. Replay is an audit
operation: it performs no provider, tool, proposal, memory, or project-file
side effect and does not reconstruct private input or output.

The lifecycle fold accepts only the ordered worker/grant/start prefix, at most
one cancellation event, and one terminal receipt event at the end. It rejects
duplicates, reordering, `memory.projected`, post-terminal appends, partial
valid-looking success/failure prefixes, and cancellation/outcome
contradictions.

## Crash and recovery boundary

Every ordinary store session acquires and retains a shared OS lock on the
persistent one-byte `agent-events.lock` file before opening SQLite. A dedicated
`AgentEventLog.recovery(root)` session must acquire the same byte exclusively
and non-blockingly. Ordinary sessions cannot mark recovery; recovery sessions
cannot begin, append, or finalize, and there is no in-process lock upgrade.
Consequently an open prefix can be marked only while all ordinary sessions are
closed or have exited. POSIX uses non-blocking shared/exclusive `flock`; Windows
uses non-blocking shared/exclusive `LockFileEx`.

Recovery requires an existing regular, one-link database before SQLite is
opened. While holding the exclusive fence, it retains and hashes the main
database plus any durable WAL and rollback-journal sidecars, observes but does
not copy SHM lock state, and copies at most 64 MiB of cumulative stable bytes
into an exclusive temporary sibling directory outside the store. Descriptor,
pathname, size, and hash evidence must remain exact before and after copying
and detached validation. The detached copy validates WAL structure and
checksums, applies any WAL or rollback recovery only in the temporary
namespace, and revalidates version, exact schema, lock binding, foreign keys,
private state, public documents, and lifecycle.

Only after that detached preflight passes may recovery open the original with
an existing-database-only connection and repeat exact identity, schema, and
state checks. Only an ordinary session may initialize the private schema; a
missing, empty, replaced, unknown, or corrupt recovery store is never created
or migrated. A failed recovery preflight leaves the original main database and
its WAL, SHM, and rollback-journal namespace and bytes unchanged.

Each instance is bound to its constructor process ID. An inherited POSIX fork
copy rejects every operational API; child cleanup closes only its inherited
descriptor and never issues `LOCK_UN` against the parent's lock description.
Owner-process close releases the recovery fence only after SQLite close
succeeds. A failed close retains state and the fence for a later owner-thread
retry. Forgotten owner instances use the same SQLite-then-lock order during
bounded best-effort finalization and fail closed if SQLite cannot close.

An open prefix is owned only by the live store session that began it. After a
close, crash, indeterminate mutation, or reopen, it must never be resumed,
retried, finalized, or given a synthesized receipt or private output. An
exclusive recovery session may list it and use exact generation/sequence/head
compare-and-swap to mark it `recovery_required`. That state is durable audit
evidence only. This design makes no exactly-once claim for provider, tool,
proposal, or any other external side effect.

## Persistence and security boundary

The store persists no raw private input or output, provider payload, model
history, tool arguments, proposal payload, operational path, credential,
token, or secret. The lock must remain a regular, one-link file containing one
NUL byte. Its retained device/inode identity is bound into schema metadata and
is rechecked with the root, database, and WAL/SHM/rollback-journal identities at
store boundaries. Path checks reject link/reparse roots; linked or hard-linked
lock, database, and sidecar files; detectable pathname substitution; and
unsupported or known non-local filesystems. They reduce accidental aliasing and
same-host substitution risk; they are not a sandbox or a complete defense
against a malicious process with the same UID.

Code running inside the owning process is trusted by this slice. Code that can
reach the private SQLite connection or retained lock descriptor can close,
duplicate, or otherwise sabotage those resources; the lock is not a security
boundary against malicious same-process code. Process isolation and descriptor
custody belong to a future host control-plane decision.

The private state hash detects incoherent projections. It is not a MAC or an
authenticity proof. A same-UID process able to replace the complete store and
all coherent hashes outside the checked identity windows remains outside this
slice. Stronger authenticity, OS isolation, custody, backup, and key management
belong to a future host control-plane decision.

## Compatibility

The five public Agent Harness v1 schemas, catalog entries, generated Studio
types, and canonical fixtures remain byte-identical. Published receipt
`replay_support` remains `not_claimed`: durable audit reread is not deterministic
provider replay. Legacy runtime and `src/isoworld` are unchanged.

## Proven boundary

Bounded local tests prove close/reopen audit replay, canonical persistence,
successful and cancelled terminal chains, exact duplicate handling, concurrent
and stale-writer CAS rejection, ambiguous-commit reconciliation, atomic
receipt/final-event rollback, conservative crash recovery, zero-adapter replay,
pagination, privacy sentinels, schema/version rejection, document/state/
relational/lifecycle tamper detection, and the path attacks that repository
primitives can detect. Linux spawned-process tests prove shared coexistence,
exclusive recovery exclusion after broker activation but before provider invocation,
lock release after clean close or abrupt process exit, and byte-preserving
rejection of unknown version, schema corruption, foreign-key corruption, and a
checksum-corrupt WAL retained after a crash. Windows lock mode and remote-drive
decisions are seam-tested only in this local evidence.

## Not proven

This slice does **not** prove a real provider/model or billing record, a Studio
job/recovery UI, process isolation or hard kill, external MCP safety, memory
approval/projection, asset promotion, deterministic provider replay,
same-UID full-store authenticity, backups, native Windows lock behavior, or
hosted/native/release evidence.
