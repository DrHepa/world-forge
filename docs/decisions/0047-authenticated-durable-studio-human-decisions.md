# ADR-0047: Authenticated durable Studio human decisions

- Status: accepted
- Date: 2026-08-30

## Context

ADR-0035 deliberately limits the Agent Harness authority to an in-memory,
unauthenticated reviewer label. Studio now needs a private backend authority
that can retain a Director possession check and exact approval evidence across
a service restart without changing published Harness, worker, EventLog, or
Studio protocol bytes.

## Decision

StudioStore schema v6 adds an additive, transactional private authority. There
is exactly one `director_local` credential. Enrollment is explicit and primary
store only; missing, deleted, or malformed credential state never enrolls or
recovers itself. The store records a random 32-byte salt, the fixed scrypt
parameters `N=32768`, `r=8`, `p=1`, `dklen=32`, `maxmem=67108864`, and a
domain-separated HMAC-SHA256 verifier. That verifier authenticates strict
compact canonical JSON for a closed credential-v1 envelope containing its
format/version, credential ID, every KDF parameter, lowercase hexadecimal salt,
and enrollment timestamp; only the verifier itself is excluded. A passphrase is
encoded as supplied in UTF-8 and must be 16 through 1024 bytes: it is not trimmed
or normalized. Neither passphrase, scrypt master, nor HMAC subkeys is persisted.
Credential and decision-event timestamps have one accepted representation:
valid UTC calendar time as `YYYY-MM-DDTHH:MM:SS.ffffffZ`, with exactly six
fractional digits and literal `Z`. Parsing must round-trip byte-identically;
offset or precision variants are not aliases.

Unlock checks the fixed verifier with constant-time comparison and then audits
the whole private decision chain before returning an authority. Every event is
strict compact canonical JSON with a SHA-256 content hash, previous content
hash, and an HMAC-SHA256 under an event-only derived key. The audit rejects
gaps, reorder, noncanonical bytes, changed MAC/hash, invalid transition,
projection mismatch, and malformed review or decision before any authority use.
The authenticated event-v1 document is closed to exactly its twelve defined
top-level keys; an otherwise validly rehashed and re-MACed extension is not a
v1 event. Its authenticated `updated_at`, relational event `created_at`, and
current projection timestamp must all resolve to the same canonical value.
StudioStore owns a separate private SQLite connection and lock for this
authority: unlock verifies the credential and reads the full event/projection
audit in one deferred transaction snapshot, while transitions use
`BEGIN IMMEDIATE`. Commits or rollbacks through the Store's ordinary manager
connection therefore cannot split an authenticated transition. The ordinary
connection retains SQLite's default thread affinity; only the dedicated
authority connection permits cross-thread use, serialized by its actual lock.
The private v6 boundary is an exact relational contract rather than a
required-column subset. Primary creation/migration, secondary attachment,
private-connection creation, and every authority transaction verify the exact
three-table/one-explicit-index object census, normalized authored DDL, ordered
column metadata, primary and unique indexes, foreign-key targets and actions,
the deferred approval relation, and all authored checks. Authority-prefixed
tables, indexes, views, or triggers outside that census are rejected. Live
authority connections also require foreign-key enforcement enabled and ignored
check constraints disabled before any state is trusted or mutated.
Because SQLite identifiers are case-insensitive, object discovery case-folds
every schema name and owning-table name before applying the private authority
prefix; the expected seven object names themselves must still match exactly.
The Store must be closed by the thread that created its ordinary connection; a
foreign-thread close rejects before changing terminal state or detaching either
connection. Creator-thread close is permanent and idempotent: under the
authority lock it marks the Store closed before detaching and closing both
connections. Connection creation and every authority transaction recheck that
exact live Store-owned connection, so close either waits for the in-flight
transaction or prevents it from starting; no later call can resurrect the
private connection.

Unlock freezes the exact persisted credential evidence and a monotonic
`(event_id, content_hash)` live anchor without retaining the passphrase or
scrypt master. Every later snapshot, authorization check, and transition
revalidates that credential, the complete event chain, the anchor, and the
exact projection within its own SQLite snapshot. Writes audit both before and
after their projection/event mutation, then advance the anchor only after a
successful commit. This detects independent projection or event mutation and
the loss of a suffix already observed by that live authority.

A SQLite commit error is an ambiguous acknowledgement, not proof that the
transaction committed or rolled back. A read that already completed its exact
audit retains that observed head after safely ending its transaction, while
still returning failure. A failed write acknowledgement is reconciled under
the authority lock by ending any still-active transaction and auditing a new
snapshot: only the exact pre-mutation or exact post-audit head is accepted and
anchored. The original call always fails; a later explicit exact retry follows
the normal idempotency rule. If cleanup or reconciliation cannot establish one
of those two states, that authority instance is permanently poisoned and
rejects later use.

Non-ordinary interruption is not converted into an ordinary Studio failure.
Every enrollment, unlock, read, write, rollback, commit, and reconciliation
boundary performs the same cleanup discipline for `BaseException`: a proved
rollback retains the authority, ambiguous writes use the exact pre/post-head
reconciliation above, and uncertain bootstrap or live cleanup invalidates the
Store boundary or poisons the authority respectively. The first interruption
remains authoritative and is re-raised unchanged after cleanup; a later
cleanup interruption cannot replace it. The failed operation never reports
success, including when its write may already have committed.

Each bootstrap and live transaction places `BEGIN`, its complete body and
audits, `COMMIT`, and anchor publication in one lexical protected region. An
outer fail-close boundary surrounds the region's first-outcome handler, so an
interruption delivered while retaining an anchor, rolling back, or reconciling
cannot escape as the reported outcome or leave the boundary reusable without
an exact cleanup result. Phase state is advanced before commit becomes
ambiguous; reconciliation itself similarly protects its recovery transaction
from `BEGIN` through observed-head publication. A completed live entry audit
publishes its trusted head to a fail-close recovery slot before returning, so
an interruption while the caller stores that result must either retain the
exact observation or leave the authority poisoned.

An ordinary domain or SQLite failure already latched before audited-head
retention remains the primary outward outcome if that retention is interrupted.
The authority is poisoned first, bounded rollback still runs, and the secondary
interruption is retained only as cleanup-uncertainty context; the authority
cannot be used again.

The same precedence applies when the later interruption lands on the exception
binding or first-failure latch itself. The outer boundary recovers only the
immediate active `__context__`, rejects self-reference and direct context/cause
cycles, and never walks farther through an exception chain. Write-commit
stabilization is called directly inside that outer-protected handler rather
than through an adjacent handler-local `try` entry that could become an
unprotected opcode boundary.

Enrollment and unlock have no safely returned authority instance on which to
record that poison. If either operation cannot prove its rollback, or if its
commit acknowledgement fails, the Store detaches and best-effort closes the
private connection and permanently disables that private authority boundary
for the lifetime of that Store object. The failed call never acknowledges
enrollment or unlock. A newly opened Store may inspect durable state and retry;
the uncertain Store never reconnects or reuses the handle. A proved rollback,
including an ordinary wrong-passphrase failure, does not disable the boundary.

The authority accepts the existing immutable `ExecutionApprovalReview` and
`ExecutionApprovalDecision` objects unchanged. It only accepts the existing
`agent_tool_approval` semantics: an exact review begins at generation 0,
approved or denied decision is generation 1, and revocation is generation 2.
Both live decision submission and reconstruction of persisted approved, denied,
or revoked evidence require `reviewer_id` to be exactly `director_local`.
Every authenticated transition compare-and-swaps the current projection and
appends its event in one SQLite transaction. Exact retries are idempotent;
different or stale replay loses. Approval expires exclusively at
`now_ms >= expires_at_ms`.

Private entry points reuse the Harness exact identifier, lowercase SHA-256, and
safe-integer validators: subclasses and booleans are not accepted as their base
types, and integers are bounded by the existing maximum safe integer. The
backend exposes the existing authority seam's `fingerprint_hashes`, `snapshot`,
`check_snapshot`, and `check` behavior. `check_snapshot` preserves the caller's
preselected immutable snapshot, never adopts a later decision, and re-audits
the live credential, complete chain, projection, revocation, and exact current
row in one read transaction before authorization. API parity does not connect
this backend to Harness execution or constitute Studio hydration.

This is a backend-only private Python API. It adds no Electron ceremony, Studio
service operation, protocol field, or Harness hydration bridge. Those require a
later independently reviewed implementation, rather than an unactionable UI
placeholder or implied user workflow.

## Limitations

The credential proves only possession of a locally enrolled passphrase. The
verifier permits offline guessing. This design does not claim civil or OS
identity, legal attribution, hardware-backed custody, nonrepudiation, secure
key entry, keylogging resistance, unlocked-process resistance, Python memory
zeroization, swap/core-dump protection, or protection from a compromised Studio
main process. Corruption can deny service. A valid whole-store rollback or tail
truncation presented to a fresh process before unlock cannot be detected
without an external monotonic anchor; the in-memory live anchor only protects
history observed since enrollment or unlock. Commit reconciliation is likewise
process-local and does not turn an ambiguous SQLite/driver acknowledgement into
an external durability or anti-rollback claim. Cleanup is bounded and
fail-closed; it does not claim immunity to indefinitely repeated process-level
interruptions or termination that prevents Python cleanup from running. Native
and hosted platform evidence has not been added; unavailable platforms remain
untested.

## Compatibility

The v5-to-v6 migration is additive and atomic for primary stores. Secondary
stores require exact schema v6 and never migrate. Existing v1-v5 Studio,
Harness, worker, and EventLog records and protocol bytes are untouched.
